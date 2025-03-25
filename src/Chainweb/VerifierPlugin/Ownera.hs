{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE PackageImports #-}

-- | Implementation of Hyperlane natives.
module Chainweb.VerifierPlugin.Ownera
  ( OwneraSchemaId(..)
  , decodeFinApiHashList
  , decodeFinApiData
  , hashListSchema
  , owneraSchemaIdToText
  , textToOwneraSchemaId
  , plugin
  , verifyOwneraData
  , testVerify
  ) where

import Control.Lens ((^?), at, _Just)
import Control.Monad (when,forM_)
import Control.Monad.Except

import Data.Map (Map,fromList,lookup)
import Data.Text (Text,unpack,pack)
import Data.Text.Lazy (toStrict)
import qualified Data.Set as Set

import qualified Data.List as List

import qualified Data.Text.Encoding as T
import qualified Data.Text.Lazy.Encoding as TL

import Pact.Core.Pretty hiding (dot)
import Data.Traversable
import Data.Decimal()


import qualified Data.ByteArray as ByteArray

import Data.ByteString.Builder

import Pact.Core.Errors (VerifierError(..))
import Pact.Core.PactValue
import Pact.Core.Names

import Pact.Types.Capability


import Data.Vector(Vector,toList,(!?))

import Text.Read(readMaybe)


import Crypto.Hash as Hash

import Chainweb.VerifierPlugin

import Chainweb.Pact.Conversion

import Crypto.Curve.Secp256k1 (parse_point, Projective(..))


import           Crypto.Number.Serialize (os2ip)
import           Crypto.PubKey.ECC.ECDSA (PublicKey(..), Signature(..), verifyDigest)
import           Crypto.PubKey.ECC.Types (CurveName(SEC_p256k1), getCurveByName, Point(..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
-- import           Data.Maybe (fromMaybe)

import qualified Data.Binary.Put (runPut, putWord8, putByteString)
import qualified Data.ByteString.Lazy (toStrict)


plugin :: VerifierPlugin
plugin = VerifierPlugin $ \_ proof caps gasRef -> do
  chargeGas gasRef 100
  -- extract capability values
  msgArgs <- case Set.toList caps of
    [cap] -> do
       case mapM fromLegacyPactValue (_scArgs cap) of
         Left s -> throwError $ VerifierError $ "LegacyError: " <> pack s
         Right mav -> return $ mav
         -- Right _ -> throwError $ VerifierError "Unexpected proof data. Expected: object"

    _ -> throwError $ VerifierError "Expected one capability."
  (sId , hld) <- case fromLegacyPactValue proof of
    Left s -> throwError $ VerifierError $ "LegacyError: " <> pack s
    -- Right _ -> throwError (VerifierError testVerify) 
    Right (PObject pvm) -> liftEither $ verifyOwneraData pvm
    Right _ -> throwError $ VerifierError "Unexpected cap data. Expected: object"
  liftEither $ verifyCapArgs sId msgArgs hld
    
data OwneraSchemaId =
      Deposit
    | PrimarySale
    | SecondarySale
    | Loan
    | Redeem
    | Withdraw

-- Function to convert OwneraSchemaId to lowercase Text with hyphens, using LambdaCase
owneraSchemaIdToText :: OwneraSchemaId -> Text
owneraSchemaIdToText = \case
    Deposit        -> "deposit"
    PrimarySale    -> "primary-sale"
    SecondarySale  -> "secondary-sale"
    Loan           -> "loan"
    Redeem         -> "redeem"
    Withdraw       -> "withdraw"

-- Map to associate Text representation with OwneraSchemaId
owneraSchemaIdMap :: Map Text OwneraSchemaId
owneraSchemaIdMap = fromList
    [ ("deposit", Deposit)
    , ("primary-sale", PrimarySale)
    , ("secondary-sale", SecondarySale)
    , ("loan", Loan)
    , ("redeem", Redeem)
    , ("withdraw", Withdraw)
    ]

owneraOperationNameSchemaIdMap :: Map Text OwneraSchemaId
owneraOperationNameSchemaIdMap = fromList
    [ ("deposit", Deposit)
    , ("issue", PrimarySale)
    , ("transfer", SecondarySale)
    , ("loan", Loan)
    , ("redeem", Redeem)
    , ("withdraw", Withdraw)
    ]


textToOwneraSchemaId :: Text -> Either VerifierError OwneraSchemaId
textToOwneraSchemaId txt =
    case Data.Map.lookup txt owneraSchemaIdMap of
        Just schemaId -> Right schemaId
        Nothing       -> Left $ VerifierError $ "Invalid schema ID: " <> txt


operationToOwneraSchemaId :: Text -> Either VerifierError OwneraSchemaId
operationToOwneraSchemaId txt =
    case Data.Map.lookup txt owneraOperationNameSchemaIdMap of
        Just schemaId -> Right schemaId
        Nothing       -> Left $ VerifierError $ "Invalid operation name: " <> txt


grabStrField :: Map Field PactValue -> Field ->  Either VerifierError Text
grabStrField m key = case m ^? at key . _Just . _PString of
  Nothing -> Left (VerifierError (_field key))
  Just t -> Right t

grabObjField :: Map Field PactValue -> Field ->  Either VerifierError (Map Field PactValue)
grabObjField m key = case m ^? at key . _Just . _PObject of
  Nothing -> Left (VerifierError (_field key))
  Just t -> Right t

grabListField :: Map Field PactValue -> Field ->  Either VerifierError (Vector PactValue)
grabListField m key = case m ^? at key . _Just . _PList of
  Nothing -> Left (VerifierError (_field key))
  Just t -> Right t

-- grabHashGroup :: Map Field PactValue -> Field ->  Either VerifierError (Map Field PactValue)
-- grabHashGroup m key = case m ^? at key . _Just of
--   Just (PObject o) -> Right o
--   _ -> Left (VerifierErrorFailedToFindHashGroup key)
  

newtype HashListGroupSchema = HashListGroupSchema [Field]
newtype HashListSchema = HashListSchema [(Field , HashListGroupSchema)]

data HashListData =  HashListData
 { _hldHash :: Text
 , _hldData :: [Text] 
 }

data HashListsData = HashListsData
 { _hlsdSignature :: Text
 , _hlsdHash      :: Text
 , _hlsdData      :: [HashListData]
 }


-- hashTest :: Either VerifierError ()
-- hashTest = Left $ VerifierError $
--    toStrict $ TL.decodeUtf8 $ toLazyByteString $ byteStringHex $ ByteArray.convert $ hashFinalize $
--              hashUpdates (hashInitWith SHA3_256 ) $
--                  (map T.encodeUtf8 ["abcd"])
  
verifyHashListDataHash :: HashListData -> Either VerifierError ()
verifyHashListDataHash hld =
  let calculatedHash = toStrict $ TL.decodeUtf8 $ toLazyByteString $ byteStringHex $ ByteArray.convert $ hashFinalize $
             hashUpdates (hashInitWith SHA3_256 ) $
                 (map T.encodeUtf8 (reverse (_hldData hld)))
  in if calculatedHash == _hldHash hld
     then Right ()
     else Left $ VerifierError $ calculatedHash <> " =/= " <>  _hldHash hld 
        
hashListDataAsPactValue :: HashListGroupSchema -> HashListData -> PactValue
hashListDataAsPactValue (HashListGroupSchema xs) (HashListData _ ys) =
   PObject $
    fromList $
      map (\x@(Field f , v) ->
            case (f , v) of
              ("amount" , PString s) -> (Field f ,
                                           case (readMaybe $ unpack s) of
                                             Just d -> PDecimal d
                                             _ -> PString s)
              _  -> x)
        (zip xs (fmap PString ys))
  

hashListsDataAsPactValue :: HashListSchema -> HashListsData -> PactValue
hashListsDataAsPactValue (HashListSchema ys) (HashListsData _ _ xs) = 
   PObject $
    fromList $
      [ (hgK ,  hashListDataAsPactValue hgS hgV) | ((hgK , hgS) , hgV) <- zip ys xs  ] 

  
hashListSchema :: OwneraSchemaId -> HashListSchema
hashListSchema = HashListSchema . hls .
  \case
    Deposit ->
     [("DHG" ,
          ["nonce"
          ,"operation"
          ,"assetType"
          ,"assetId"
          ,"dstAccountType"
          ,"dstAccount"
          ,"amount"])]
                
    PrimarySale ->
     [("AHG" ,
          [ "nonce"
          , "operation"
          , "assetType"
          , "assetId"
          , "dstAccountType"
          , "dstAccount"
          , "amount"])
          ,
      ("SHG" , 
          ["assetType"
          ,"assetId"
          ,"srcAccountType"
          ,"srcAccount"
          ,"dstAccountType"
          ,"dstAccount"
          , "amount"])]
    SecondarySale  ->
        [(("AHG"),
          ["nonce"
          ,"operation"
          ,"assetType"
          ,"assetId"
          ,"srcAccountType"
          ,"srcAccount"       
          ,"dstAccountType"
          ,"dstAccount"
          ,"amount"])
        ,(("SHG"),
           ["assetType"
           ,"assetId"
           ,"srcAccountType"
           ,"srcAccount"
           ,"dstAccountType"
           ,"dstAccount"
           ,"amount"])]

          
          
     
    Loan           ->
     [("HG",["nonce"
            ,"operation"
            ,"pledgeAssetType"
            ,"pledgeAssetId"
            ,"pledgeBorrowerAccountType"
            ,"pledgeBorrowerAccountId"
            ,"pledgeLenderAccountType"
            ,"pledgeLenderAccountId"
            ,"pledgeAmount"          
            ,"moneyAssetType"
            ,"moneyAssetId"
            ,"moneyLenderAccountType"
            ,"moneyLenderAccountId"
            ,"moneyBorrowerAccountType"
            ,"moneyBorrowerAccountId"
            ,"borrowedMoneyAmount"
            ,"returnedMoneyAmount"
            ,"openTime"
            ,"closeTime"])]
    Redeem         ->
     [("AHG",["nonce"
             ,"operation"
             ,"assetType"
             ,"assetId"
             ,"srcAccountType"
             ,"srcAccount"          
             ,"amount"])

     ,("SHG",["assetType"
             ,"assetId"
             ,"srcAccountType"
             ,"srcAccount"
             ,"dstAccountType"
             ,"dstAccount"
             ,"amount"])]

    Withdraw       ->
     [("HG" , ["nonce"
              ,"operation"
              ,"assetType"
              ,"assetId"
              ,"srcAccountType"
              ,"srcAccount"
              ,"dstAccountType"
              ,"dstAccount"
              ,"amount"])]

 where
   hls :: [(Text , [Text])] -> [(Field , HashListGroupSchema)]
   hls = fmap (\(x , y) -> (Field x , HashListGroupSchema (fmap Field y)))

hashListSchemaCheckedFields :: OwneraSchemaId -> Either VerifierError  [(Int , Field)]
hashListSchemaCheckedFields = \case   
    PrimarySale -> return [(0 , Field f) | f <- ["assetId","amount","dstAccount"]]
    SecondarySale -> return [(0 , Field f) | f <- ["assetId","amount","srcAccount","dstAccount"]]
    _ -> Left $ VerifierError "OwneraError: Unimplemented"
  
recogniseSchema :: Map Field PactValue -> Either VerifierError OwneraSchemaId
recogniseSchema obj = do
  tObj <- grabObjField obj (Field "template")
  hgsLst <- grabListField tObj (Field "hashGroups")
  case hgsLst !? 0 of
    Just (PObject hg) -> do
       fLst <- grabListField hg (Field "fields")
       case fLst !? 1 of
        Just (PObject fo) -> do
          grabStrField fo (Field "value")
            >>= operationToOwneraSchemaId
        _ -> Left (VerifierError ("unable to recognise schema, operation field missing"))
        
    _ -> Left (VerifierError ("unable to recognise schema, first hash group missing"))
          
           
         
  
extractOfSchema :: HashListSchema -> Map Field PactValue ->
                          (Either VerifierError HashListsData)
extractOfSchema (HashListSchema hls) dObj = do
   sig <- grabStrField dObj (Field "signature")
   tObj <- grabObjField dObj (Field "template")
   _ <- grabStrField tObj (Field "type")
   h <- grabStrField tObj (Field "hash")
  
   hgsLst <- grabListField tObj (Field "hashGroups")
   accumRes <- mapAccumM 
         (curry (\case
             ([] , _) -> Left $
                 VerifierError ("unexpected hash group!")
             (((_  , HashListGroupSchema hgFlds) : flds) , (PObject fldDataO)) -> do
                  hgFldsVec <- grabListField fldDataO (Field "fields")
                  h' <- grabStrField fldDataO (Field "hash")
                  ((,) flds . HashListData h') <$> consumeHashGroupFields hgFlds hgFldsVec
             (_ , _) -> Left $
                 VerifierError ("hash group must by an object!")
               )) hls hgsLst
   case accumRes of
     ([] , x) -> pure (HashListsData sig h $ toList x)
     (unconsumedHGs , _) -> Left $
       VerifierError ("missing hashGroups: " <>
                           (renderText' $ commaSep (fmap fst unconsumedHGs)))

 where

   
  consumeHashGroupFields :: [Field] -> Vector PactValue ->
                         Either VerifierError [Text]
  consumeHashGroupFields flds' vpv =
      mapAccumM (curry (\case
             ([] , _) -> Left $
                 VerifierError ("unexpected field in hash group!")
             ((fld : flds) , (PObject fobj)) -> do
                  n <- grabStrField fobj (Field "name")
                  _ <- grabStrField fobj (Field "type")
                  v <- grabStrField fobj (Field "value")
                  if (Field n) == fld
                    then pure (flds , v)
                    else Left $ VerifierError
                           ("expected field: " <> renderText fld <> " unexpectly got: " <> n)
             ((_ : _) , _) -> Left $
                 VerifierError ("unexpected value!")
               )) flds' vpv
        >>= \case
              ([] , x) -> pure $ toList x
              (flds , _) -> Left $
                         VerifierError ("missing fields in hashGroup: " <>
                           (renderText' $ commaSep flds))
      
     

decodeFinApiData :: OwneraSchemaId -> Map Field PactValue -> Either VerifierError PactValue
decodeFinApiData osId pKV = do
   extracted <- extractOfSchema (hashListSchema osId) pKV
   when False $
      mapM_ verifyHashListDataHash (_hlsdData extracted)
   pure $ hashListsDataAsPactValue (hashListSchema osId) extracted

decodeFinApiHashList :: OwneraSchemaId -> Map Field PactValue -> Either VerifierError HashListsData
decodeFinApiHashList osId pKV = do
   extracted <- extractOfSchema (hashListSchema osId) pKV
   when True $
      mapM_ verifyHashListDataHash (_hlsdData extracted)
   return extracted

lookupHashListsData :: HashListsData -> OwneraSchemaId -> Int -> Field -> Either VerifierError PactValue
lookupHashListsData hashListsData schemaId idx field = do
  -- Get the correct schema for provided OwneraSchemaId
  let (HashListSchema hashGroupSchemas) = hashListSchema schemaId

  -- Ensure the index is within bounds
  groupSchema <- case hashGroupSchemas List.!? idx of
    Just (_, grp) -> Right grp
    Nothing -> Left $ VerifierError $ "Invalid HashList index: " <> pack (show idx)

  -- Get the HashListData at the index provided
  hashListData <- case (_hlsdData hashListsData) List.!? idx of
    Just hld -> Right hld
    Nothing -> Left $ VerifierError $ "No HashListData found at index: " <> pack (show idx)

  -- Extract fields and their values from the schema and HashListData
  let HashListGroupSchema fieldsInGroup = groupSchema
  let fieldValuePairs = zip fieldsInGroup (_hldData hashListData)

  -- Lookup the provided field
  case List.lookup field fieldValuePairs of
    Just txtValue -> Right $ PString txtValue
    Nothing -> Left $ VerifierError $ "Field " <> renderText field <> " not found in HashList at index " <> pack (show idx)

verifyCapArgs :: OwneraSchemaId -> [PactValue] -> HashListsData -> Either VerifierError ()
verifyCapArgs schemaId pactValues hashListsData = do
  -- Retrieve the specification of fields to cross-check
  checkedFields <- hashListSchemaCheckedFields schemaId

  -- Ensure the provided PactValues list has the expected length
  when (length pactValues /= length checkedFields) $
    Left $ VerifierError "Mismatch between provided PactValues and expected fields count"

  -- Cross-check each PactValue against the data in HashListsData
  forM_ (zip pactValues checkedFields) $ \(pv, (idx, field@(Field fieldName))) -> do
    expectedValue <- lookupHashListsData hashListsData schemaId idx field

    -- Special treatment for fields named "amount": attempt conversion to decimal
    pvAdjusted <- case (fieldName, expectedValue) of
      ("amount", PString expectedStr) ->
        case (readMaybe (unpack expectedStr)) of
          (Just expectedDec) -> pure (pv, PDecimal expectedDec)
          _ -> Left $ VerifierError "Fatal in verifyCapArgs"
          
      _ -> pure (pv, expectedValue)

    when (fst pvAdjusted /= snd pvAdjusted) $
      Left $ VerifierError $
              "Value mismatch for field " <> renderText field <> " at index " <> pack (show idx)
           <> " expected: " <> pactValueToText expectedValue
           <> " provided: " <> pactValueToText pv


  -- All checks passed
  pure ()


verifyOwneraData :: Map Field PactValue -> Either VerifierError (OwneraSchemaId , HashListsData)
verifyOwneraData pkV = do
  sId <- recogniseSchema pkV
  d <- decodeFinApiHashList sId pkV
  pure (sId , d)



-- Correct hexToBS function for recent base16-bytestring versions
hexToBS :: BS.ByteString -> Maybe BS.ByteString
hexToBS hex = either (const Nothing) Just (B16.decode hex)


-- | Serializes a Projective point to its uncompressed form.
serialize_uncompressed :: Projective -> BS.ByteString
serialize_uncompressed (Projective x y _) =
    Data.ByteString.Lazy.toStrict $ Data.Binary.Put.runPut $ do
        Data.Binary.Put.putWord8 0x04  -- Uncompressed key prefix
        Data.Binary.Put.putByteString (integerToBS x)
        Data.Binary.Put.putByteString (integerToBS y)
  where
    -- Converts an Integer to a 32-byte big-endian ByteString
    integerToBS :: Integer -> BS.ByteString
    integerToBS i = BS.pack $ reverse $ take 32 $ reverse (unroll i) ++ replicate 32 0
    unroll 0 = []
    unroll n = fromIntegral (n `mod` 256) : unroll (n `div` 256)
    
decompressPublicKey :: BS.ByteString -> Maybe BS.ByteString
decompressPublicKey compressedKey = do
    point <- parse_point compressedKey
    return $ serialize_uncompressed point
    

parsePubKey :: BS.ByteString -> Maybe PublicKey
parsePubKey hex = do
  bytes <- hexToBS hex
  -- Import the compressed public key
  bytes' <- decompressPublicKey bytes
  case BS.uncons bytes' of
    Just (0x04, rest) | BS.length rest == 64 -> do
      let (xBytes, yBytes) = BS.splitAt 32 rest
          x = os2ip xBytes
          y = os2ip yBytes
          curve = getCurveByName SEC_p256k1
      return $ PublicKey curve (Point x y)
    _ -> Nothing
    
parseSignature :: BS.ByteString -> Maybe Signature
parseSignature hex = do
  bytes <- hexToBS hex
  if BS.length bytes == 64 then
    let (rBytes, sBytes) = BS.splitAt 32 bytes
        r = os2ip rBytes
        s = os2ip sBytes
    in Just $ Signature r s
  else
    Nothing


verifySecp256k1Signature :: BS.ByteString -- ^ Hex-encoded SHA3_256 hash of message (32 bytes)
                         -> BS.ByteString -- ^ Hex-encoded signature (64 bytes, R || S)
                         -> BS.ByteString -- ^ Hex-encoded public key (33 bytes) (compressed format)
                         -> Maybe Bool
verifySecp256k1Signature msgHex sigHex pubKeyHexComp =
 
  case (hexToBS msgHex, parseSignature sigHex, parsePubKey pubKeyHexComp) of
    (Just msgHash, Just sig, Just pk) ->
      case Hash.digestFromByteString msgHash :: Maybe (Hash.Digest Hash.SHA3_256) of
        Just digest -> Just (verifyDigest pk sig digest)
        Nothing     -> Nothing
    _ -> Nothing
    
-- | Example Usage:
testVerify :: Text
testVerify = 
  let msgHex =    "319581118dc6e2af7a5d92b5e149bed108bd03f2c214371ff28d9ca81206ad60" -- "hello world" in hex
      sigHex = "db96110667579fd876c6b74d8fd848d29d0fb22f114c912202661010a27ef5087b3c9e33fc9af83e1f025e7d180612c7fc0c5f847a61e348dd35309855b29a44"
      pubKeyHex = "03c48631f1d9ca0c89d8da8c7268e4d44f4223737829a9316d940352da3b25c40d"
  in case verifySecp256k1Signature msgHex sigHex pubKeyHex of
   Just True ->  "Signature is valid!"
   Just False -> "Signature is invalid!"
   Nothing -> "Format is invalid!"
