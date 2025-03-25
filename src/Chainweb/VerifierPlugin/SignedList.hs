{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- A very small and generic verifier–plugin.
--
-- The plugin expects the proof-value to be a list of three items
--
--   1. list –    a Pact list of literal strings (the message parts)
--   2. pubKey –  hex-encoded, *compressed* Secp256k1 public key (33 bytes)
--   3. sig –     hex-encoded signature (64 bytes, R || S)
--
-- The corresponding capability must contain *exactly* the same three
-- arguments in the same order.
--
-- Verification steps performed:
--   • Message hash  =  SHA3-256 over the UTF-8 concatenation of the list
--     elements (no separators).
--   • Signature is verified against the supplied compressed public key
--     using the Ownera helper (secp256k1 / SHA3-256).
--
-- If any check fails, the transaction is aborted with a VerifierError.
--
module Chainweb.VerifierPlugin.SignedList (plugin) where

import           Control.Monad                       (unless, forM)
import           Control.Monad.Except
import qualified Data.Set                            as Set
import qualified Data.Text                           as Text
import qualified Data.Text.Encoding                  as TextEnc
import qualified Data.Vector                         as V
import qualified Data.ByteString                     as BS
import qualified Data.ByteString.Base16              as B16
import qualified Data.ByteString.Short               as SBS
import           Data.ByteArray                      (convert)
import           Crypto.Hash                         (hashWith, SHA3_256(..))
import qualified Crypto.Hash                         as Hash
import           Crypto.Number.Serialize             (os2ip)
import           Crypto.PubKey.ECC.ECDSA             (PublicKey(..), Signature(..), verifyDigest)
import           Crypto.PubKey.ECC.Types             (CurveName(SEC_p256k1), getCurveByName, Point(..))
import           Crypto.Secp256k1                    (ecdsaPublicKeyFromCompressed, ecdsaPublicKeyBytes)

import           Pact.Core.Errors                    (VerifierError(..))
import           Pact.Types.PactValue
import           Pact.Types.Capability               (SigCapability(..))
import           Pact.Types.Exp                      (Literal(..))

import           Chainweb.VerifierPlugin             (VerifierPlugin(..), chargeGas)

-------------------------------------------------------------------------------
-- | entry-point
-------------------------------------------------------------------------------
plugin :: VerifierPlugin
plugin = VerifierPlugin $ \_ proof caps gasRef -> do

  -- Small fixed gas cost for the generic checks.
  chargeGas gasRef 100

  ---------------------------------------------------------------------------
  -- 1. Extract the requested capability and its arguments
  ---------------------------------------------------------------------------
  (capArgs :: [PactValue]) <- case Set.toList caps of
    [SigCapability{_scArgs = as}] -> pure as
    _ -> throwError $ VerifierError "Expected exactly one capability"

  -- Expected layout of capability arguments: [ list , key , sig ]
  (capMsgParts, capPubKeyTxt, capSigTxt) <- case capArgs of
    [PList lst, PLiteral (LString pkTxt), PLiteral (LString sigTxt)] ->
      pure (lst, pkTxt, sigTxt)
    _ -> throwError $ VerifierError "Capability arguments must be: (list string-values, pubKey, signature)"

  ---------------------------------------------------------------------------
  -- 2. Parse and validate the proof – it must mirror the cap arguments
  ---------------------------------------------------------------------------
  (msgParts, pubKeyTxt, sigTxt) <- case proof of
    PList vec
      | [PList lst, PLiteral (LString pk), PLiteral (LString sig)] <- V.toList vec
      -> pure (lst, pk, sig)
    _ -> throwError $ VerifierError "Proof must be a list: [ values , pubKey , signature ]"

  unless (msgParts == capMsgParts && pubKeyTxt == capPubKeyTxt && sigTxt == capSigTxt) $
    throwError $ VerifierError "Capability arguments do not match the proof data"

  ---------------------------------------------------------------------------
  -- 3. Build the message hash (SHA3-256 over concatenated UTF-8 bytes)
  ---------------------------------------------------------------------------
  rawBytes <- fmap BS.concat $ forM (V.toList msgParts) $ \case
    PLiteral (LString t) -> pure (TextEnc.encodeUtf8 t)
    _ -> throwError $ VerifierError "Only literal strings are allowed inside the values list"

  let msgDigest      = hashWith SHA3_256 rawBytes          -- 32 bytes
      msgHashHexBS   = B16.encode (convert msgDigest)      -- 64-byte hex

  ---------------------------------------------------------------------------
  -- 4. Perform the ECDSA verification (secp256k1 / SHA3-256)
  ---------------------------------------------------------------------------
  let cleanHex x = if "0x" `Text.isPrefixOf` x then Text.drop 2 x else x
      sigHexBS   = TextEnc.encodeUtf8 (cleanHex sigTxt)
      pkHexBS    = TextEnc.encodeUtf8 (cleanHex pubKeyTxt)

  -- Substantial gas cost for the cryptographic check (same as other plugins)
  chargeGas gasRef 20000

  isValid <- case verifySecp256k1Signature msgHashHexBS sigHexBS pkHexBS of
               Just v  -> pure v
               Nothing -> throwError $ VerifierError "Malformed hex inputs for signature verification"

  unless isValid $ throwError $ VerifierError "Signature verification failed"

  -- Success – all checks passed.
  pure ()

-------------------------------------------------------------------------------
-- Cryptographic helpers (adapted from Ownera.Crypto)
-------------------------------------------------------------------------------

verifySecp256k1Signature
  :: BS.ByteString  -- ^ Hex-encoded SHA3-256 hash of message (32 bytes)
  -> BS.ByteString  -- ^ Hex-encoded signature (64 bytes, R || S)
  -> BS.ByteString  -- ^ Hex-encoded compressed public key (33 bytes)
  -> Maybe Bool
verifySecp256k1Signature msgHex sigHex pubKeyHexComp =
  case (hexToBS msgHex, parseSignature sigHex, parsePubKey pubKeyHexComp) of
    (Just msgHash, Just sig, Just pk) ->
      case Hash.digestFromByteString msgHash :: Maybe (Hash.Digest SHA3_256) of
        Just digest -> Just (verifyDigest pk sig digest)
        Nothing     -> Nothing
    _ -> Nothing

-------------------------------------------------------------------------------
-- Helpers
-------------------------------------------------------------------------------

hexToBS :: BS.ByteString -> Maybe BS.ByteString
hexToBS hex = either (const Nothing) Just (B16.decode hex)

-- | Decompress a compressed (33-byte) secp256k1 public key.

decompressPublicKey :: BS.ByteString -> Maybe BS.ByteString
decompressPublicKey compressedKey = do
  let short = SBS.toShort compressedKey
  pk <- either (const Nothing) Just (ecdsaPublicKeyFromCompressed short)
  pure (SBS.fromShort (ecdsaPublicKeyBytes pk))

-- | Parse an (uncompressed) 65-byte public key into the representation that
-- the ECDSA verification functions expect.
parsePubKey :: BS.ByteString -> Maybe PublicKey
parsePubKey hex = do
  bytes <- hexToBS hex
  bytes' <- decompressPublicKey bytes
  case BS.uncons bytes' of
    Just (0x04, rest) | BS.length rest == 64 -> do
      let (xBytes, yBytes) = BS.splitAt 32 rest
          x               = os2ip xBytes
          y               = os2ip yBytes
          curve           = getCurveByName SEC_p256k1
      pure (PublicKey curve (Point x y))
    _ -> Nothing

parseSignature :: BS.ByteString -> Maybe Signature
parseSignature hex = do
  bytes <- hexToBS hex
  if BS.length bytes == 64
     then let (rBytes, sBytes) = BS.splitAt 32 bytes
              r = os2ip rBytes
              s = os2ip sBytes
          in Just (Signature r s)
     else Nothing
