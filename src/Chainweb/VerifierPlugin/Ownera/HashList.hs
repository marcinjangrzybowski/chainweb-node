{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Parsing and verification of FIN/P2P "hash-list" messages for the Ownera
-- schema.  Relies on declarative definitions found in
-- 'Chainweb.VerifierPlugin.Ownera.Types'.  The module remains completely
-- /pure/: it performs no IO and its only side-effects are returned through
-- 'Either VerifierError'.

module Chainweb.VerifierPlugin.Ownera.HashList where

import Control.Lens               ((^?), at, _Just)
import Control.Monad              (when)
import Data.Text                  (Text)
import qualified Data.Text as Text
import qualified Data.Text.Lazy as TLText
import qualified Data.Text.Encoding as T
import qualified Data.Text.Lazy.Encoding as TL

import Data.Map (Map, fromList)

import Data.Vector (Vector)
import qualified Data.Vector as V

import Data.Traversable (mapAccumM)
import qualified Data.List as List

import Crypto.Hash (SHA3_256(..))
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as ByteArray
import Data.ByteString.Builder (byteStringHex, toLazyByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16

import Pact.Core.Errors   (VerifierError(..))
import Pact.Core.Names    (Field(..))
import Pact.Core.PactValue
import Pact.Core.Pretty   (commaSep, renderText, renderText')

import Text.Read (readMaybe)

-- --------------------------------------------------------------------------
-- Hash list schema description
-- --------------------------------------------------------------------------

newtype HashListGroupSchema = HashListGroupSchema [Field]
    deriving (Eq, Show)

newtype HashListSchema = HashListSchema [(Field , HashListGroupSchema)]
    deriving (Eq, Show)

-- | Data found inside an individual hash-group.
data HashListData = HashListData
  { _hldHash   :: Text              -- ^ 256-bit group hash (hex-encoded)
  , _hldFields :: [(Text, Text)]    -- ^ (type, value) pairs, original order
  }
  deriving (Eq, Show)

-- | Convenience accessor that throws away the type tag.
_hldData :: HashListData -> [Text]
_hldData = fmap snd . _hldFields

-- | Fully-parsed template: signature, template hash and the ordered groups.
data HashListsData = HashListsData
  { _hlsdSignature :: Text
  , _hlsdHash      :: Text
  , _hlsdData      :: [HashListData]
  }
  deriving (Eq, Show)


--------------------------------------------------------------------------
-- Tiny helpers to grab fields from a PactValue object
--------------------------------------------------------------------------

grabStrField :: Map Field PactValue -> Field -> Either VerifierError Text
grabStrField m key = case m ^? at key . _Just . _PString of
  Nothing -> Left (VerifierError (_field key))
  Just t  -> Right t

grabObjField :: Map Field PactValue -> Field -> Either VerifierError (Map Field PactValue)
grabObjField m key = case m ^? at key . _Just . _PObject of
  Nothing -> Left (VerifierError (_field key))
  Just t  -> Right t

grabListField :: Map Field PactValue -> Field -> Either VerifierError (Vector PactValue)
grabListField m key = case m ^? at key . _Just . _PList of
  Nothing -> Left (VerifierError (_field key))
  Just t  -> Right t

--------------------------------------------------------------------------
-- Hex helpers (kept local to avoid crypto module dependency cycle)
--------------------------------------------------------------------------

hexToBS :: BS.ByteString -> Maybe BS.ByteString
hexToBS bs = either (const Nothing) Just (B16.decode bs)

--------------------------------------------------------------------------
-- Hash-group integrity checks
--------------------------------------------------------------------------

-- | Verify that the hash stored for one hash-group matches the SHA3-256 hash
-- of its concatenated /raw/ field bytes (according to their declared types).
verifyHashListDataHash :: HashListData -> Either VerifierError ()
verifyHashListDataHash hld = do
  payload <- fmap BS.concat . traverse (uncurry toBytes) $ _hldFields hld

  let digest        = Hash.hashWith SHA3_256 payload
      calculatedHex = toStrictText
                    $ toLazyByteString (byteStringHex (ByteArray.convert digest :: BS.ByteString))
      expectedHex   = _hldHash hld

  if calculatedHex == expectedHex
     then pure ()
     else Left . VerifierError $ calculatedHex <> " =/= " <> expectedHex
  where
    toStrictText = TLText.toStrict . TL.decodeUtf8

    -- Convert a single field value to its binary representation.
    toBytes :: Text -> Text -> Either VerifierError BS.ByteString
    toBytes typTxt valTxt = case typTxt of
      "string" -> Right (T.encodeUtf8 valTxt)
      "bytes"  -> decodeHex valTxt
      "[]byte" -> decodeHex valTxt
      _         -> Left (VerifierError $ "Unsupported field type: " <> typTxt)

    -- Hex-decoder that tolerates an optional 0x prefix.
    decodeHex :: Text -> Either VerifierError BS.ByteString
    decodeHex t = case B16.decode (T.encodeUtf8 t) of
      Right bs -> Right bs
      Left e   -> Left (VerifierError $ "Invalid hex encoding: " <> Text.pack e)

--------------------------------------------------------------------------
-- Schema-driven parsing of a FIN/P2P message
--------------------------------------------------------------------------

-- | Low-level worker that extracts the template from the JSON/Pact object
-- according to the declared 'HashListSchema'.
extractOfSchema :: HashListSchema -> Map Field PactValue -> Either VerifierError HashListsData
extractOfSchema (HashListSchema hls) dObj = do
  sig  <- grabStrField dObj (Field "signature")
  tObj <- grabObjField dObj (Field "template")
  _    <- grabStrField tObj (Field "type")
  h    <- grabStrField tObj (Field "hash")

  hgsLst <- grabListField tObj (Field "hashGroups")

  (leftOver, vec) <- mapAccumM (curry step) hls hgsLst
  case leftOver of
    [] -> pure (HashListsData sig h (V.toList vec))
    xs -> Left . VerifierError $ "missing hashGroups: " <> renderText' (commaSep (fmap fst xs))
  where
    step :: ([(Field, HashListGroupSchema)], PactValue)
         -> Either VerifierError ([(Field, HashListGroupSchema)], HashListData)
    step = \case
      ([], _) -> Left (VerifierError "unexpected hash group!")
      (((_f, HashListGroupSchema hgFlds) : flds), PObject fldDataO) -> do
        hgFldsVec <- grabListField fldDataO (Field "fields")
        h' <- grabStrField fldDataO (Field "hash")
        fieldsData <- consumeHashGroupFields hgFlds hgFldsVec
        pure (flds, HashListData h' fieldsData)
      (_, _) -> Left (VerifierError "hash group must be an object!")

    consumeHashGroupFields
      :: [Field]
      -> Vector PactValue
      -> Either VerifierError [(Text, Text)]
    consumeHashGroupFields flds' vpv =
      mapAccumM inner flds' vpv >>= \case
        ([], xs) -> pure (V.toList xs)
        (missing, _) -> Left (VerifierError $ "missing fields in hashGroup: " <> renderText' (commaSep missing))

    inner :: [Field] -> PactValue -> Either VerifierError ([Field], (Text, Text))
    inner [] _ = Left (VerifierError "unexpected field in hash group!")
    inner (fld:flds) (PObject fobj) = do
      n <- grabStrField fobj (Field "name")
      t <- grabStrField fobj (Field "type")
      v <- grabStrField fobj (Field "value")
      if Field n == fld
        then pure (flds, (t, v))
        else Left (VerifierError $ "expected field: " <> renderText fld <> " unexpectedly got: " <> n)
    inner (_:_) _ = Left (VerifierError "unexpected value!")

--------------------------------------------------------------------------
-- Parent-hash verification
--------------------------------------------------------------------------

verifyParentHash :: HashListsData -> Either VerifierError ()
verifyParentHash hlsd = do
  grpBytes <- traverse decodeHash (_hlsdData hlsd)

  let digest   = Hash.hashWith SHA3_256 (BS.concat grpBytes)
      calcHash = normaliseHex (toStrictText (toLazyByteString (byteStringHex (ByteArray.convert digest :: BS.ByteString))))
      expected = normaliseHex (_hlsdHash hlsd)

  when (calcHash /= expected) . Left . VerifierError $ "Parent/template hash mismatch. expected " <> expected <> " but calculated " <> calcHash
  where
    toStrictText = TLText.toStrict . TL.decodeUtf8

    decodeHash :: HashListData -> Either VerifierError BS.ByteString
    decodeHash hld =
      let txt = normaliseHex (_hldHash hld)
      in case hexToBS (T.encodeUtf8 txt) of
           Just bs | BS.length bs == 32 -> Right bs
           _ -> Left (VerifierError $ "Invalid group hash encoding: " <> _hldHash hld)

    normaliseHex t = let t' = if "0x" `Text.isPrefixOf` t then Text.drop 2 t else t in Text.toLower t'

--------------------------------------------------------------------------
-- Conversion helpers (HashList* -> PactValue)
--------------------------------------------------------------------------

hashListDataAsPactValue :: HashListGroupSchema -> HashListData -> PactValue
hashListDataAsPactValue (HashListGroupSchema xs) (HashListData _ ys) =
  PObject . fromList . map convert $ List.zip xs (fmap (PString . snd) ys)
  where
    convert x@(Field f, v) = case (f, v) of
      ("amount", PString s) ->
        case readMaybe (Text.unpack s) of
          Just d  -> (Field f, PDecimal d)
          Nothing -> x
      _ -> x

hashListsDataAsPactValue :: HashListSchema -> HashListsData -> PactValue
hashListsDataAsPactValue (HashListSchema ys) (HashListsData _ _ xs) =
  PObject . fromList $ [ (hgK, hashListDataAsPactValue hgS hgV) | ((hgK, hgS), hgV) <- List.zip ys xs ]
