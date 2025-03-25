{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Pure, declarative data-types and helper functions that describe the
-- FIN/P2P Ownera schema.  This module has no dependency on hashing or crypto
-- code and can therefore be shared by the parsing and crypto layers.

module Chainweb.VerifierPlugin.Ownera.Types  where


import Control.Monad (forM_, when)
import Data.Map (Map, fromList)
import qualified Data.Map as Map
import qualified Data.List as List
import qualified Data.Text as Text
import Data.Text (Text)
import Text.Read (readMaybe)


import Data.Vector ((!?))

import Pact.Core.Errors (VerifierError(..))
import Pact.Core.Names (Field(..))
import Pact.Core.PactValue
import Pact.Core.Pretty   (renderText)

import Chainweb.VerifierPlugin.Ownera.HashList

-- --------------------------------------------------------------------------
-- Ownera schema identifier
-- --------------------------------------------------------------------------

data OwneraSchemaId
    = Deposit
    | PrimarySale
    | SecondarySale
    | Loan
    | Redeem
    | Withdraw
    deriving (Eq, Show)

-- | Convert a schema identifier to its canonical lower-case textual form.
owneraSchemaIdToText :: OwneraSchemaId -> Text
owneraSchemaIdToText = \case
    Deposit        -> "deposit"
    PrimarySale    -> "primary-sale"
    SecondarySale  -> "secondary-sale"
    Loan           -> "loan"
    Redeem         -> "redeem"
    Withdraw       -> "withdraw"

-- | Mapping from textual identifier to 'OwneraSchemaId'.
owneraSchemaIdMap :: Map Text OwneraSchemaId
owneraSchemaIdMap = fromList
    [ ("deposit", Deposit)
    , ("primary-sale", PrimarySale)
    , ("secondary-sale", SecondarySale)
    , ("loan", Loan)
    , ("redeem", Redeem)
    , ("withdraw", Withdraw)
    ]

textToOwneraSchemaId :: Text -> Either VerifierError OwneraSchemaId
textToOwneraSchemaId t =
    case Map.lookup t owneraSchemaIdMap of
      Just s  -> Right s
      Nothing -> Left (VerifierError $ "Invalid schema ID: " <> t)

-- | Mapping from FIN/P2P "operation" names to schema identifiers.  Note that
-- these names are *not* always identical to the textual schema IDs, e.g.
-- "issue" maps to 'PrimarySale'.
owneraOperationNameSchemaIdMap :: Map Text OwneraSchemaId
owneraOperationNameSchemaIdMap = fromList
    [ ("deposit", Deposit)
    , ("issue", PrimarySale)
    , ("transfer", SecondarySale)
    , ("loan", Loan)
    , ("redeem", Redeem)
    , ("withdraw", Withdraw)
    ]

operationToOwneraSchemaId :: Text -> Either VerifierError OwneraSchemaId
operationToOwneraSchemaId t =
    case Map.lookup t owneraOperationNameSchemaIdMap of
      Just s  -> Right s
      Nothing -> Left (VerifierError $ "Invalid operation name: " <> t)


-- --------------------------------------------------------------------------
-- Ownera signature schemes definitions
-- --------------------------------------------------------------------------

-- -- | For every supported schema we list the hash-groups and the names of the
-- -- fields within each group.  The order is significant.
-- -- (https://finp2p-docs.ownera.io/reference/signature-schemes)

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


-- | Which fields are cross-checked against capability arguments for a given
-- schema.  The list is @(hashGroupIndex, Field)@.
hashListSchemaCheckedFields :: OwneraSchemaId -> Either VerifierError [(Int, Field)]
hashListSchemaCheckedFields = \case
    PrimarySale    -> Right [(0, Field f) | f <- ["assetId", "amount", "dstAccount"]]
    SecondarySale  -> Right [(0, Field f) | f <- ["assetId", "amount", "srcAccount", "dstAccount"]]
    _              -> Left (VerifierError "OwneraError: Unimplemented")


-- | Fine-grained combined schema and intent representation
data SchemaIntent
  = DepositRecipient
  | PrimarySaleInitiator
  | SecondarySaleInitiator
  | SecondarySaleRecipient
  | WithdrawInitiator
  | LoanInitiator
  | LoanRecipient
  | RedeemInitiator
  deriving (Eq, Show)

-- | Extract the signer key (finId) from the message based on SchemaIntent
extractSignerKey
  :: SchemaIntent
  -> HashListsData
  -> Either VerifierError PactValue
extractSignerKey schemaIntent hashListsData =
  case schemaIntent of

    DepositRecipient ->
      lookupHashListsData hashListsData Deposit 0 (Field "dstAccount")

    PrimarySaleInitiator ->
      lookupHashListsData hashListsData PrimarySale 1 (Field "srcAccount")

    SecondarySaleInitiator ->
      lookupHashListsData hashListsData SecondarySale 1 (Field "srcAccount")

    SecondarySaleRecipient ->
      lookupHashListsData hashListsData SecondarySale 0 (Field "srcAccount")

    WithdrawInitiator ->
      lookupHashListsData hashListsData Withdraw 0 (Field "srcAccount")

    LoanInitiator ->
      lookupHashListsData hashListsData Loan 0 (Field "pledgeBorrowerAccountId")

    LoanRecipient ->
      lookupHashListsData hashListsData Loan 0 (Field "moneyLenderAccountId")

    RedeemInitiator ->
      lookupHashListsData hashListsData Redeem 0 (Field "srcAccount")

--------------------------------------------------------------------------
-- Bridging to Pact capability arguments
--------------------------------------------------------------------------

-- | Locate a value inside a fully parsed 'HashListsData' using the schema
-- description.
lookupHashListsData :: HashListsData -> OwneraSchemaId -> Int -> Field -> Either VerifierError PactValue
lookupHashListsData hashListsData schemaId idx field = do
  let HashListSchema hashGroupSchemas = hashListSchema schemaId

  groupSchema <- case hashGroupSchemas List.!? idx of
    Just (_, grp) -> Right grp
    Nothing       -> Left (VerifierError $ "Invalid HashList index: " <> Text.pack (show idx))

  hashListData <- case _hlsdData hashListsData List.!? idx of
    Just hld -> Right hld
    Nothing  -> Left (VerifierError $ "No HashListData found at index: " <> Text.pack (show idx))

  let HashListGroupSchema fieldsInGroup = groupSchema
      fieldValuePairs = List.zip fieldsInGroup (_hldData hashListData)

  case List.lookup field fieldValuePairs of
    Just txtValue -> Right (PString txtValue)
    Nothing       -> Left (VerifierError $ "Field " <> renderText field <> " not found in HashList at index " <> Text.pack (show idx))

-- | Cross-check capability arguments against data contained in the message.
verifyCapArgs :: OwneraSchemaId -> [PactValue] -> HashListsData -> Either VerifierError ()
verifyCapArgs schemaId pactValues hashListsData = do
  checkedFields <- hashListSchemaCheckedFields schemaId

  when (length pactValues /= length checkedFields) $
    Left (VerifierError "Mismatch between provided PactValues and expected fields count")

  forM_ (List.zip pactValues checkedFields) $ \(pv, (idx, field@(Field fieldName))) -> do
    expectedValue <- lookupHashListsData hashListsData schemaId idx field

    -- special handling for decimal amounts
    let (pv', expected') = case (fieldName, expectedValue) of
          ("amount", PString expectedStr) -> case readMaybe (Text.unpack expectedStr) of
              Just expectedDec -> (pv, PDecimal expectedDec)
              _                -> (pv, expectedValue)
          _ -> (pv, expectedValue)

    when (pv' /= expected') $
      Left (VerifierError $ "Value mismatch for field " <> renderText field <> " at index " <> Text.pack (show idx) <>
            " expected: " <> pactValueToText expected' <>
            " provided: " <> pactValueToText pv')

-- | Parse the message, returning both its schema identifier and the fully
-- checked 'HashListsData'.
verifyOwneraData :: Map Field PactValue -> Either VerifierError (OwneraSchemaId, HashListsData)
verifyOwneraData pkv = do
  sId <- recogniseSchema pkv
  d   <- decodeFinApiHashList sId pkv
  pure (sId, d)

--------------------------------------------------------------------------
-- Schema recognition (peek at the operation field in the first group)
--------------------------------------------------------------------------

recogniseSchema :: Map Field PactValue -> Either VerifierError OwneraSchemaId
recogniseSchema obj = do
  tObj   <- grabObjField obj (Field "template")
  hgsLst <- grabListField tObj (Field "hashGroups")
  case hgsLst !? 0 of
    Just (PObject hg) -> do
      fLst <- grabListField hg (Field "fields")
      case fLst !? 1 of
        Just (PObject fo) -> grabStrField fo (Field "value") >>= operationToOwneraSchemaId
        _ -> Left (VerifierError "unable to recognise schema, operation field missing")
    _ -> Left (VerifierError "unable to recognise schema, first hash group missing")

--------------------------------------------------------------------------

--------------------------------------------------------------------------
-- High-level API
--------------------------------------------------------------------------

-- | Decode a FIN/P2P message, verify *all* hashes and return the embedded
-- data as a Pact object.
decodeFinApiData :: OwneraSchemaId -> Map Field PactValue -> Either VerifierError PactValue
decodeFinApiData sId pKV = do
  extracted <- extractOfSchema (hashListSchema sId) pKV
  mapM_ verifyHashListDataHash (_hlsdData extracted)
  pure $ hashListsDataAsPactValue (hashListSchema sId) extracted

-- | Same as 'decodeFinApiData' but returns the fully-typed 'HashListsData'.
decodeFinApiHashList :: OwneraSchemaId -> Map Field PactValue -> Either VerifierError HashListsData
decodeFinApiHashList sId pKV = do
  extracted <- extractOfSchema (hashListSchema sId) pKV
  -- 1. Verify individual group hashes
  mapM_ verifyHashListDataHash (_hlsdData extracted)
  -- 2. Verify parent/template hash
  verifyParentHash extracted
  pure extracted
