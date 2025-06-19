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
v = pact5InstantCpmTestVersion petersenChainGraph

chain0 :: ChainId
chain0 = unsafeChainId 0

owneraExampleMsgProof :: Aeson.Value
owneraExampleMsgProof = [aesonQQ|
[{
    "signature": "db96110667579fd876c6b74d8fd848d29d0fb22f114c912202661010a27ef5087b3c9e33fc9af83e1f025e7d180612c7fc0c5f847a61e348dd35309855b29a44",
    "template": {
      "hash": "319581118dc6e2af7a5d92b5e149bed108bd03f2c214371ff28d9ca81206ad60",
      "hashGroups": [
        {
          "fields": [
            {
              "name": "nonce", "type": "bytes", "value": "16f56a399856b1a6243f5b9afb3e523ea73294be4c95ef0a0000000066d97261"
            },
            {
              "name": "operation", "type": "string", "value": "issue"
            },
            {
              "name": "assetType", "type": "string", "value": "finp2p"
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
              "value": "1"
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
  },"initiator"]
|]

owneraExampleMsgProofSnd :: Aeson.Value
owneraExampleMsgProofSnd = [aesonQQ|
[{
      "signature": "f63ad86f46ca9dd381b3715c8cc2544f9443457103a14ee8abb5bb6dbac4bdac1a775ea8f78d032ad24ad886ecdd1069977ee2a960b31037cb06f69578d239ae",
      "template": {
        "hash": "f0239389596aa35f75b9cb4a5481d9e1bd98032a5b89045b9a4b63a1dbd51948",
        "hashGroups": [
          {
            "fields": [
              { "name": "nonce",          "type": "bytes",   "value":
"945075f8cca6c1fdf9f82e0fd8585399419efdc195633996000000006851b6ed" },
              { "name": "operation",      "type": "string",  "value": "transfer" },
              { "name": "assetType",      "type": "string",  "value": "finp2p" },
              { "name": "assetId",        "type": "string",  "value":
"lsegpoc1-sellside-1:102:19c1d156-20cb-44dc-9975-99b72b01a5b3" },
              { "name": "srcAccountType", "type": "string",  "value": "finId" },
              { "name": "srcAccount",     "type": "string",  "value":
"0373338d69b2cf7f82ffb873eb6da18dfd1e970faf964e532981d9325ff5b3c038" },
              { "name": "dstAccountType", "type": "string",  "value": "finId" },
              { "name": "dstAccount",     "type": "string",  "value":
"02fd8306e3c1ad2a769fbb3947720af4be92c4a1a43b5198664eb428f3872695ca" },
              { "name": "amount",         "type": "string",  "value": "10" }
            ],
            "hash": "8eb2a8781bd6a4f6ad38a7c8dd805f039eaeab04439d0f143c049a348a23bbe2"
          },
          {
            "fields": [
              { "name": "assetType",      "type": "string",  "value": "fiat" },
              { "name": "assetId",        "type": "string",  "value": "USD" },
              { "name": "srcAccountType", "type": "string",  "value": "finId" },
              { "name": "srcAccount",     "type": "string",  "value":
"02fd8306e3c1ad2a769fbb3947720af4be92c4a1a43b5198664eb428f3872695ca" },
              { "name": "dstAccountType", "type": "string",  "value": "finId" },
              { "name": "dstAccount",     "type": "string",  "value":
"0373338d69b2cf7f82ffb873eb6da18dfd1e970faf964e532981d9325ff5b3c038" },
              { "name": "amount",         "type": "string",  "value": "1000000" }
            ],
            "hash": "2706f86799aff21e6958122405b482d52103143babbb86814971a2a3ff41e295"
}]}}
,"initiator"]
|]
  
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
                , "(defun x () (with-capability (K \"citi:102:d0c3eb56-0fff-4670-adfd-ad291a4314c3\" 1.0 \"02fd7923740a775c95ce17e9bb7239ff9096689f70db9263a7efb9a9ad08e9fed7\") 1)))"
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
                    ,PDecimal 1
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
                , "(defun x () (with-capability (K \"lsegpoc1-sellside-1:102:19c1d156-20cb-44dc-9975-99b72b01a5b3\" 10.0 \"0373338d69b2cf7f82ffb873eb6da18dfd1e970faf964e532981d9325ff5b3c038\" \"02fd8306e3c1ad2a769fbb3947720af4be92c4a1a43b5198664eb428f3872695ca\") 1)))"
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
                    [PString "lsegpoc1-sellside-1:102:19c1d156-20cb-44dc-9975-99b72b01a5b3"
                    ,PDecimal 10
                    ,PString "0373338d69b2cf7f82ffb873eb6da18dfd1e970faf964e532981d9325ff5b3c038"
                    ,PString "02fd8306e3c1ad2a769fbb3947720af4be92c4a1a43b5198664eb428f3872695ca"
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
