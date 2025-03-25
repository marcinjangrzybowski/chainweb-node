{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Chainweb.Test.Pact5.OwneraPluginTests (tests) where

import Control.Lens
import Control.Monad.IO.Class
import Control.Monad.Trans.Resource

import Data.Aeson qualified as Aeson

import Data.Aeson.QQ.Simple

import PropertyMatchers ((?))
import PropertyMatchers qualified as P
import Test.Tasty
import Test.Tasty.HUnit (testCaseSteps)

import Chainweb.Graph
import Chainweb.Storage.Table.RocksDB (RocksDb)
import Chainweb.Test.Pact5.CmdBuilder
import Chainweb.Test.Pact5.CutFixture (advanceAllChains_)
import Chainweb.Test.Pact5.RemotePactTest hiding (tests)
import Chainweb.Test.Pact5.Utils
import Chainweb.Test.TestVersions
import Chainweb.Test.Utils

import Chainweb.Version
import Pact.Core.Command.Types
import Pact.Core.Gas
import Pact.Core.Names
import Pact.Core.PactValue
import Pact.Core.Capabilities
import Pact.Core.Verifiers
import Pact.Core.Signer

tests :: RocksDb -> TestTree
tests baseRdb = testGroup "Pact5 OwneraPluginTests"
    [ testCaseSteps "owneraValidatorTest"
        $ owneraValidatorTest baseRdb
    , testCaseSteps "owneraValidatorTestSnd"
        $ owneraValidatorTestSnd baseRdb
    ]

v :: ChainwebVersion
v = pact5InstantCpmTestVersion petersonChainGraph

chain0 :: ChainId
chain0 = unsafeChainId 0


owneraExampleMsgProof :: Aeson.Value
owneraExampleMsgProof = [aesonQQ|
{
      "signature": "db96110667579fd876c6b74d8fd848d29d0fb22f114c912202661010a27ef5087b3c9e33fc9af83e1f025e7d180612c7fc0c5f847a61e348dd35309855b29a44",
      "template": {
        "hash": "319581118dc6e2af7a5d92b5e149bed108bd03f2c214371ff28d9ca81206ad60",
        "hashGroups": [
          {
      "fields": [
        {
          "name": "nonce",
          "type": "bytes",
          "value": "16f56a399856b1a6243f5b9afb3e523ea73294be4c95ef0a0000000066d97261"
        },
        {
          "name": "operation",
          "type": "string",
          "value": "issue"
        },
        {
          "name": "assetType",
          "type": "string",
          "value": "finp2p"
        },
        {
          "name": "assetId",
          "type": "string",
          "value": "citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3"
        },
        {
          "name": "dstAccountType",
          "type": "string",
          "value": "finId"
        },
        {
          "name": "dstAccount",
          "type": "string",
          "value": "02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7"
        },          
        {
          "name": "amount",
          "type": "string",
          "value": "25"
        }
      ],
      "hash": "faf3fd67e908cd840298a6f3523631716d4c8df06d69c9a32415f59eaa56825d"
          },
          {
      "fields": [
        {
          "name": "assetType",
          "type": "string",
          "value": "fiat"
        },
        {
          "name": "assetId",
          "type": "string",
          "value": "USD"
        },
        {
          "name": "srcAccountType",
          "type": "string",
          "value": "finId"
        },
        {
          "name": "srcAccount",
          "type": "string",
          "value": "02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7"
        },
        {
          "name": "dstAccountType",
          "type": "string",
          "value": "finId"
        },
        {
          "name": "dstAccount",
          "type": "string",
          "value": "03c48631f1d9ca0c89d8da8c7268e4d44f4223737829a9316d940352da3b25c40d"
        },
        {
          "name": "amount",
          "type": "string",
          "value": "10"
        }
      ],
      "hash": "e8a6bc590ed71a70e2507ad842a237cf55bbb751abb38fca61c0c83c4b07bd5f"
          }
        ],
        "type": "hashList"
      }
    }
|]

owneraExampleMsgProofSnd :: Aeson.Value
owneraExampleMsgProofSnd = [aesonQQ|
{
      "signature": "b1444d7981bd543a24510a178a21a917ee261bcb531d4ef4dbee318e90a4992b30c995f232f87a3d993d8c7e4814cfe7552b6f9825de6dfe8b19b61ab7ffba0b",
      "template": {
        "hash": "5413f45cc5b03b0036f418813c96cbe469efe3f13395c19ff330955858636349",
        "hashGroups": [
          {
            "fields": [
              {
                "name": "nonce",
                "type": "bytes",
                "value": "39fc89491a957fc72e12d7eb703c0bd23cd5c54ff612b97f0000000066d97bb6"
              },
              {
                "name": "operation",
                "type": "string",
                "value": "transfer"
              },
              {
                "name": "assetType",
                "type": "string",
                "value": "finp2p"
              },
              {
                "name": "assetId",
                "type": "string",
                "value": "citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3"
              },
              {
                "name": "srcAccountType",
                "type": "string",
                "value": "finId"
              },
              {
                "name": "srcAccount",
                "type": "string",
                "value": "02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7"
              },
              {
                "name": "dstAccountType",
                "type": "string",
                "value": "finId"
              },
              {
                "name": "dstAccount",
                "type": "string",
                "value": "0354916de33408d1e30f638fc5920a57166867ded48c0f9098baf5f1a6c1c76676"
              },
              {
                "name": "amount",
                "type": "string",
                "value": "10"
              }
            ],
            "hash": "1d36e25dcd84e29597d9e923446cb13930a8e59bf6cbbca02ee5909e290443a2"
          },
          {
            "fields": [
              {
                "name": "assetType",
                "type": "string",
                "value": "fiat"
              },
              {
                "name": "assetId",
                "type": "string",
                "value": "USD"
              },
              {
                "name": "srcAccountType",
                "type": "string",
                "value": "finId"
              },
              {
                "name": "srcAccount",
                "type": "string",
                "value": "0354916de33408d1e30f638fc5920a57166867ded48c0f9098baf5f1a6c1c76676"
              },
              {
                "name": "dstAccountType",
                "type": "string",
                "value": "finId"
              },
              {
                "name": "dstAccount",
                "type": "string",
                "value": "02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7"
              },
              {
                "name": "amount",
                "type": "string",
                "value": "20"
              }
            ],
            "hash": "e18bc18f23990e4a155bdce1afa9b15ef118624133b9af6401e84814a9d9bcf3"
          }
        ],
        "type": "hashList"
      }
  }
|]

-- fiatUSDfinId0354916de33408d1e30f638fc5920a57166867ded48c0f9098baf5f1a6c1c76676finId02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed720

-- noncebytes39fc89491a957fc72e12d7eb703c0bd23cd5c54ff612b97f0000000066d97bb6operationstringtransferassetTypestringfinp2passetIdstringciti:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3srcAccountTypestringfinIdsrcAccountstring02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7dstAccountTypestringfinIddstAccountstring0354916de33408d1e30f638fc5920a57166867ded48c0f9098baf5f1a6c1c76676amountstring10
  
owneraValidatorTest :: RocksDb -> Step -> IO ()
owneraValidatorTest baseRdb step = runResourceT $ do
    fx <- mkFixture v baseRdb
    liftIO $ do
        let pluginName = "ownera_message"

        step "deploy contract"
        deploy <- buildTextCmd v
            $ set cbGasLimit (GasLimit (Gas 100000))
            $ set cbRPC (mkExec' $ mconcat
                [ "(namespace 'free)"
                , "(module m G"
                , "(defcap G () true)"
                , "(defcap K (asset-id:string amount:decimal dst-fin-id:string) (enforce-verifier '" <> pluginName <> "))"
                , "(defun x () (with-capability (K \"citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3\" 25.0 \"02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7\") 1)))"
                ])
            $ defaultCmd chain0
        send fx v chain0 [deploy]
        advanceAllChains_ fx
        poll fx v chain0 [cmdToRequestKey deploy]
            >>= P.list [P.match _Just successfulTx]

        prf <- case (Aeson.fromJSON owneraExampleMsgProof) of
                 Aeson.Success prf -> return prf
                 _ -> error "fatal in ownera test"
                 

        step "use successfully"
        let cap =
                CapToken (QualifiedName "K" (ModuleName "m" (Just (NamespaceName "free"))) )
                    [PString "citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3"
                    ,PDecimal 25
                    ,PString "02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7"
                    ]
        usePlugin <- buildTextCmd v
            $ set cbRPC (mkExec' "(free.m.x)")
            $ set cbVerifiers
                [Verifier
                    (VerifierName pluginName)
                     prf
                    [SigCapability cap]]
            $ set cbGasLimit (GasLimit (Gas 100000))
            $ defaultCmd chain0
        send fx v chain0 [usePlugin]
        advanceAllChains_ fx
        poll fx v chain0 [cmdToRequestKey usePlugin]
            >>= P.list
                [P.match _Just ? P.checkAll
                    [ successfulTx
                    ]
                ]

owneraValidatorTestSnd :: RocksDb -> Step -> IO ()
owneraValidatorTestSnd baseRdb step = runResourceT $ do
    fx <- mkFixture v baseRdb
    liftIO $ do
        let pluginName = "ownera_message"

        step "deploy contract"
        deploy <- buildTextCmd v
            $ set cbGasLimit (GasLimit (Gas 100000))
            $ set cbRPC (mkExec' $ mconcat
                [ "(namespace 'free)"
                , "(module m G"
                , "(defcap G () true)"
                , "(defcap K (asset-id:string amount:decimal src-fin-id:string dst-fin-id:string) (enforce-verifier '" <> pluginName <> "))"
                , "(defun x () (with-capability (K \"citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3\" 10.0 \"02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7\" \"0354916de33408d1e30f638fc5920a57166867ded48c0f9098baf5f1a6c1c76676\") 1)))"
                ])
            $ defaultCmd chain0
        send fx v chain0 [deploy]
        advanceAllChains_ fx
        poll fx v chain0 [cmdToRequestKey deploy]
            >>= P.list [P.match _Just successfulTx]

        prf <- case (Aeson.fromJSON owneraExampleMsgProofSnd) of
                 Aeson.Success prf -> return prf
                 _ -> error "fatal in ownera test"
                 

        step "use successfully"
        let cap =
                CapToken (QualifiedName "K" (ModuleName "m" (Just (NamespaceName "free"))) )
                    [PString "citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3"
                    ,PDecimal 10
                    ,PString "02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7"
                    ,PString "0354916de33408d1e30f638fc5920a57166867ded48c0f9098baf5f1a6c1c76676"
                    ]
        usePlugin <- buildTextCmd v
            $ set cbRPC (mkExec' "(free.m.x)")
            $ set cbVerifiers
                [Verifier
                    (VerifierName pluginName)
                     prf
                    [SigCapability cap]]
            $ set cbGasLimit (GasLimit (Gas 100000))
            $ defaultCmd chain0
        send fx v chain0 [usePlugin]
        advanceAllChains_ fx
        poll fx v chain0 [cmdToRequestKey usePlugin]
            >>= P.list
                [P.match _Just ? P.checkAll
                    [ successfulTx
                    ]
                ]
