{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

-- | Thin façade that wires together the various sub-modules that implement
-- the Ownera verifier plugin.

module Chainweb.VerifierPlugin.Ownera
  ( -- * Re-exports
    module Chainweb.VerifierPlugin.Ownera.Types
  , module Chainweb.VerifierPlugin.Ownera.HashList
  , module Chainweb.VerifierPlugin.Ownera.Crypto

    -- * Chainweb plugin entry-point
  , plugin
  ) where

import           Control.Monad.Except                (liftEither, throwError)
import           Control.Monad                       (unless)
import qualified Data.Set                            as Set
import qualified Data.Text                           as Text
import qualified Data.Text.Encoding                  as TextEnc

import           Pact.Core.Errors                    (VerifierError(..))
import           Pact.Core.PactValue

import           Chainweb.Pact.Conversion            (fromLegacyPactValue)
import           Chainweb.VerifierPlugin             (VerifierPlugin(..), chargeGas)

-- internal modules
import           Chainweb.VerifierPlugin.Ownera.Types
import           Chainweb.VerifierPlugin.Ownera.HashList
import           Chainweb.VerifierPlugin.Ownera.Crypto

import           Pact.Types.Capability               (_scArgs)

import qualified Data.Vector                         as V

-- | The entry-point of verifier-plugin.
plugin :: VerifierPlugin
plugin = VerifierPlugin $ \_ proof caps gasRef -> do

  -- Initial fixed gas charge for Ownera checks.
  chargeGas gasRef 100

  --------------------------------------------------------------------------
  -- 1. Extract and convert capability arguments (we expect exactly one capability)
  --------------------------------------------------------------------------
  msgArgs <- case Set.toList caps of
    [cap] -> case mapM fromLegacyPactValue (_scArgs cap) of
               Left s   -> throwError (VerifierError $ "LegacyError: " <> Text.pack s)
               Right as -> pure as
    _ -> throwError (VerifierError "Expected exactly one capability")

  --------------------------------------------------------------------------
  -- 2. Decode proof payload and verify internal hash–consistency
  --------------------------------------------------------------------------
  (schemaId, hashListsData, intentTxt) <-
    case fromLegacyPactValue proof of
      Left s -> throwError (VerifierError $ "LegacyError: " <> Text.pack s)
      Right (PList l) -> case V.toList l of
        -- Proof layout expected to be: [ templateObject , intent ]
        [PObject obj, PString intent] -> do
          (sid, hld) <- liftEither (verifyOwneraData obj)
          pure (sid, hld, intent)
        _ -> throwError (VerifierError "Unexpected proof data – expected [object, string]")
      Right _ -> throwError (VerifierError "Unexpected proof data – expected list")

  --------------------------------------------------------------------------
  -- 3. Determine signer intent and extract the corresponding FinID
  --------------------------------------------------------------------------
  schemaIntent <- liftEither (intentToSchemaIntent schemaId intentTxt)
  signerPactVal <- liftEither (extractSignerKey schemaIntent hashListsData)

  signerHexText <- case signerPactVal of
    PString t -> pure t
    _         -> throwError (VerifierError "Signer FinId expected to be a string")

  --------------------------------------------------------------------------
  -- 4. Perform signature verification (secp256k1 / SHA3-256)
  --------------------------------------------------------------------------
  let cleanHex t = if Text.isPrefixOf "0x" t then Text.drop 2 t else t

      msgHashHexBS = TextEnc.encodeUtf8 (cleanHex (_hlsdHash hashListsData))
      sigHexBS     = TextEnc.encodeUtf8 (cleanHex (_hlsdSignature hashListsData))
      pubKeyHexBS  = TextEnc.encodeUtf8 (cleanHex signerHexText)

  -- Gas charge for the cryptographic verification (arbitrary constant similar to other plugins)
  chargeGas gasRef 20000

  isValid <- case verifySecp256k1Signature msgHashHexBS sigHexBS pubKeyHexBS of
               Just v  -> pure v
               Nothing -> throwError (VerifierError "Signature verification failed – malformed inputs")

  unless isValid $
    throwError (VerifierError "Invalid signature for the provided intent")

  --------------------------------------------------------------------------
  -- 5. Cross–check capability arguments with message contents
  --------------------------------------------------------------------------
  liftEither (verifyCapArgs schemaId msgArgs hashListsData)

  -- Success: all checks passed -> return unit.
  pure ()

----------------------------------------------------------------------------
-- Helpers
----------------------------------------------------------------------------

-- | Map textual intent field (second element in the proof payload) to the
-- fine–grained 'SchemaIntent', taking the message schema into account.  The
-- mapping rules follow the FIN/P2P specification.
intentToSchemaIntent :: OwneraSchemaId -> Text.Text -> Either VerifierError SchemaIntent
intentToSchemaIntent schemaId intentTxt = case (schemaId, Text.toLower intentTxt) of
  (Deposit       , "recipient")  -> Right DepositRecipient
  (PrimarySale   , "initiator")  -> Right PrimarySaleInitiator
  (SecondarySale , "initiator")  -> Right SecondarySaleInitiator
  (SecondarySale , "recipient")  -> Right SecondarySaleRecipient
  (Withdraw      , "initiator")  -> Right WithdrawInitiator
  (Loan          , "initiator")  -> Right LoanInitiator
  (Loan          , "recipient")  -> Right LoanRecipient
  (Redeem        , "initiator")  -> Right RedeemInitiator
  _ -> Left (VerifierError $ "Unsupported intent " <> intentTxt <> " for schema " <> Text.pack (show schemaId))
