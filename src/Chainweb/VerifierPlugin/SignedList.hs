{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}

--
-- The plugin expects the proof value to be structured as follows:
--
--   1. A Pact list of message parts (strings or nested structures)
--   2. A hex-encoded, compressed secp256k1 public key (33 bytes)
--   3. A hex-encoded signature (64 bytes)
--
-- The corresponding capability must contain exactly two arguments:
--
--   1. The same message parts as provided in the proof (after stripping any hashing wrappers)
--   2. The public key (matching exactly the proof's public key)
--
-- Verification process:
--   • Computes SHA3-256 over the UTF-8 concatenation of the message parts
--     (nested lists are recursively hashed and concatenated as needed).
--   • Verifies the signature using the provided public key and computed hash.
--
-- If any check fails, the transaction aborts with a VerifierError.


module Chainweb.VerifierPlugin.SignedList (plugin) where

import Control.Monad (unless, mapAndUnzipM, guard)
import Control.Monad.Except
import Data.Function ((&))

import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEnc
import qualified Data.Vector as V
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Short as SBS
import Data.ByteArray (convert)
import Crypto.Hash (hashWith, SHA3_256(..))
import qualified Crypto.Hash as Hash
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.ECC.ECDSA (PublicKey(..), Signature(..), verifyDigest)
import Crypto.PubKey.ECC.Types (CurveName(SEC_p256k1), getCurveByName, Point(..))
import Crypto.Secp256k1 (ecdsaPublicKeyFromCompressed, ecdsaPublicKeyBytes)

import Pact.Core.Errors (VerifierError(..))
import Pact.Types.PactValue
import Pact.Types.Capability (SigCapability(..))
import Pact.Types.Exp (Literal(..))
import Pact.Types.Term (objectMapToListWith)
import Pact.Types.Gas

import Chainweb.VerifierPlugin (VerifierPlugin(..), chargeGas)

--------------------------------------------------------------------------------
-- Gas Charging Parameters
--------------------------------------------------------------------------------
data GasParams = GasParams
  { baseGas          :: Gas  -- Initial validation gas cost
  , perItemGas       :: Gas  -- Gas per message part
  , hashOpGas        :: Gas  -- Gas per hashing operation
  , sigVerificationGas :: Gas -- Fixed cost for signature verification
  }

-- Default example values, should be tuned per deployment environment
gasParams :: GasParams
gasParams = GasParams
  { baseGas            = 100
  , perItemGas         = 50
  , hashOpGas          = 200
  , sigVerificationGas = 20000
  }

--------------------------------------------------------------------------------
-- Plugin Entry Point
--------------------------------------------------------------------------------
plugin :: VerifierPlugin
plugin = VerifierPlugin $ \_ proof caps gasRef -> do

  -- Base gas cost
  chargeGas gasRef (baseGas gp)

  -- Extract and validate capability arguments
  (capArgs :: [PactValue]) <- case Set.toList caps of
    [SigCapability{_scArgs = as}] -> pure as
    _ -> throwError $ VerifierError "Expected exactly one capability"

  (capMsgParts, capPubKeyTxt) <- case capArgs of
    [l@(PList _), PLiteral (LString pkTxt)] -> pure (l, pkTxt)
    _ -> throwError $ VerifierError "Capability args must be: (list, pubKey)"

  -- Parse proof structure
  (msgParts, pubKeyTxt, sigTxt) <- case proof of
    PList vec
      | [PList lst, PLiteral (LString pk), PLiteral (LString sig)] <- V.toList vec -> pure (lst, pk, sig)
    _ -> throwError $ VerifierError "Proof must be: [message parts, pubKey, sig]"

  -- Recursive hashing and gas charging
  let foldHashList = \case
        PObject om -> case objectMapToListWith (,) om of
          [("0x", PLiteral (LString b))] -> case hexToBS (TextEnc.encodeUtf8 b) of
            Just b' -> do
              chargeGas gasRef (hashOpGas gp)
              pure (b', [])
            Nothing -> throwError $ VerifierError "Malformed hex in object"
          _ -> throwError $ VerifierError "Malformed object in msg"

        PLiteral (LString t) -> do
          chargeGas gasRef (perItemGas gp)
          pure (TextEnc.encodeUtf8 t, [PLiteral (LString t)])

        PList l -> do
          chargeGas gasRef (perItemGas gp)
          (c, l') <- mapAndUnzipM foldHashList (V.toList l)
          let hashed = convert $ hashWith SHA3_256 (BS.concat c)
          chargeGas gasRef (hashOpGas gp)
          pure (hashed, [PList (V.fromList (concat l'))])

        _ -> throwError $ VerifierError "Invalid type in msg parts"

  (msgHashBS, strippedMsgParts) <- foldHashList (PList msgParts)

  unless (strippedMsgParts == [capMsgParts] && pubKeyTxt == capPubKeyTxt) $
     throwError $ VerifierError $ "Capability arguments do not match proof data: "
                  <> Text.pack (show strippedMsgParts)
                  <> " vs "
                  <> Text.pack (show [capMsgParts])

  -- Signature verification
  chargeGas gasRef (sigVerificationGas gp)

  let sigHexBS = TextEnc.encodeUtf8 sigTxt
      pkHexBS  = TextEnc.encodeUtf8 pubKeyTxt

  isValid <- case verifySecp256k1Signature msgHashBS sigHexBS pkHexBS of
    Just v  -> pure v
    Nothing -> throwError $ VerifierError "Malformed signature verification inputs"

  unless isValid $
    throwError $ VerifierError "Signature verification failed"

  -- Success: all checks passed
  pure ()

 where
 gp = gasParams
 

-- Helpers

verifySecp256k1Signature :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Maybe Bool
verifySecp256k1Signature msgHash sigHex pubKeyHexComp =
  case (parseSignature sigHex, parsePubKey pubKeyHexComp) of
    (Just sig, Just pk) -> do
      digest <- Hash.digestFromByteString msgHash :: Maybe (Hash.Digest SHA3_256)
      pure (verifyDigest pk sig digest)
    _ -> Nothing

parseSignature :: BS.ByteString -> Maybe Signature
parseSignature hex = do
  bytes <- hexToBS hex
  guard (BS.length bytes == 64)
  let (rBytes, sBytes) = BS.splitAt 32 bytes
  pure $ Signature (os2ip rBytes) (os2ip sBytes)

parsePubKey :: BS.ByteString -> Maybe PublicKey
parsePubKey hex = do
  compressed <- hexToBS hex >>= decompressPublicKey
  case BS.uncons compressed of
    Just (0x04, rest) | BS.length rest == 64 ->
      let (x, y) = BS.splitAt 32 rest
      in pure $ PublicKey (getCurveByName SEC_p256k1) (Point (os2ip x) (os2ip y))
    _ -> Nothing

decompressPublicKey :: BS.ByteString -> Maybe BS.ByteString
decompressPublicKey cKey =
    SBS.toShort cKey
  & ecdsaPublicKeyFromCompressed
  & either (const Nothing) (Just . SBS.fromShort . ecdsaPublicKeyBytes)

hexToBS :: BS.ByteString -> Maybe BS.ByteString
hexToBS = either (const Nothing) Just . B16.decode
