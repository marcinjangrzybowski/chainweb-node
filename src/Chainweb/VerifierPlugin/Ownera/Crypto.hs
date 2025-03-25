{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Low-level cryptographic helpers for Ownera verifier plugin.  The module
-- is fully self-contained and does not depend on Pact or the hash-list logic.

module Chainweb.VerifierPlugin.Ownera.Crypto
  ( verifySecp256k1Signature
  , verifySecp256k1SignatureDebug
  , testVerify
  ) where

import Crypto.Hash                      qualified as Hash
import Crypto.Hash (SHA3_256)
import Crypto.Number.Serialize          (os2ip)
import Crypto.PubKey.ECC.ECDSA          (PublicKey(..), Signature(..), verifyDigest)
import Crypto.PubKey.ECC.Types          (CurveName(SEC_p256k1), getCurveByName, Point(..))

import Crypto.Secp256k1                 (ecdsaPublicKeyFromCompressed, ecdsaPublicKeyBytes)

import Data.Maybe                       (fromMaybe)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Short  as SBS

import Data.Text (Text)

-- --------------------------------------------------------------------------
-- Helpers
-- --------------------------------------------------------------------------

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

-- --------------------------------------------------------------------------
-- High-level verification helpers
-- --------------------------------------------------------------------------

-- | Pure ECDSA verify for secp256k1 / SHA3-256.
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

-- | Same as 'verifySecp256k1Signature' but with error reasons.
verifySecp256k1SignatureDebug
  :: BS.ByteString  -- ^ message hash (hex)
  -> BS.ByteString  -- ^ signature (hex)
  -> BS.ByteString  -- ^ compressed pub key (hex)
  -> Either Text Bool
verifySecp256k1SignatureDebug msgHex sigHex pubKeyHexComp = do
  msgHash <- maybe (Left "Could not decode message hex") Right (hexToBS msgHex)
  sig     <- maybe (Left "Could not parse signature")      Right (parseSignature sigHex)
  pk      <- maybe (Left "Could not parse or decompress public key") Right (parsePubKey pubKeyHexComp)
  digest  <- maybe (Left "Message hash has wrong length")  Right (Hash.digestFromByteString msgHash :: Maybe (Hash.Digest SHA3_256))
  pure (verifyDigest pk sig digest)

-- | Quick regression test that should evaluate to @True@.
testVerify :: Bool
testVerify =
  fromMaybe False $ verifySecp256k1Signature msg sig pk
  where
    msg = "c2661e52015f6cd63f654f3b1777e01e61f4aae7f23322e3ff845ee836742fcf"
    sig = "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795bf6e8fda1fab4a87cc74bcd60aef76ea0580d976b5769d326c46c1f2eecd9f15"
    pk  = "03779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd"
