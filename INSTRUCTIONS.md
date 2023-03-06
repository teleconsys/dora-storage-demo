dOra storage demo INSTRUCTIONS
====================================

This demo will set up `nodes` able to instantiate a `committee` with the support of a `governor`. The whole system is based on communication between parties achieved through IOTA tagged data's tags. The `governor` is identified through a special, customizable tag, while every other entity possess a DID document. These entities use each other DID tags as the endpoint for peer-to-peer communication.

STEP 1 - Nodes deployment
----------------

To run the default demo, which rolls 3 nodes on the IOTA Mainnet simply run the following command in the root:

```bash
docker compose up
```

You will be using the default image `giordyfish/dora-storage-demo`. If you want to build the image by yourself, you can do so by using the provided [Dockerfile](Dockerfile).

If you want to run a node without a docker container, you can do so by running a `minio` instance for each node that you want to deploy, and then manually setting all the arguments to configure your dOra node properly when running the executable (which you must also build in release mode). You can run a dOra node with the following command: 

```bash
dora-storage node --arg value --arg value --arg value ...
```

The following table offers a brief description of all the arguments that you can pass to the executable (which you can also customize inside the [docker-compose](docker-compose.yml) file):

|       Argument       |  Default  |                                                                              Description                                                                              |
|:--------------------:|:---------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|       governor       |     /     |                                                 the governor's message tag where the nodes get instructions for DKG                                                 |
|        storage       |    None   |                                                   the storage type (minio-local is the only one supported right now)                                                  |
|   storage-endpoint   |    None   |                                                               the endpoint where the storage is located                                                               |
|  storage-access-key  |    None   |                                                                     the access key of the storage                                                                     |
|  storage-secret-key  |    None   |                                                                     the secret key of the storage                                                                     |
|       node-url       |    https://api.testnet.shimmer.network   | the Stardust Testnet node to use |
|       faucet-url       |    https://faucet.testnet.shimmer.network/api/enqueue   | the Stardust Testnet faucet API endpoint to use |
|    time-resolution   |   20 [s]  | the time resolution used to create the committee  DID Document (needed because the Document has a timestamp which will be different for every node if left unmanaged) |
| signature-sleep-time |   20 [s]  |                        the maximum time the node will wait for its peers' missing partial signatures during a distributed signature operation                        |

It is not mandatory to run every single node at the same time or inside the same machine or docker-compose network. The nodes will initialize themselves by creating their keypair and DID document and then will wait for instructions from the provided governor, that's when the committee will start to cooperate. It is mandatory to set the SAME `governor` tag for each of the nodes that you intend to be part of the same committee.

When the nodes are ready to move forward they will print a message which states that they are waiting for instructions from the `governor`.

STEP 2 - Committee creation
----------------

After the first step you are expected to have up and running some nodes (we suggest 3-5 for this demo). Each node will have generated its own DID, which is printed as an output log on the terminal. 

```
INFO  dora_storage::demo::run > node's DID document has been published
INFO  dora_storage::demo::run > node's DID is: did:iota:rms:0x88a060a7a5c3e657f0ca01624aed9e27d4026856f588e61c3d0294ae0ac02fed
INFO  dora_storage::demo::run > listening for instructions on governor tag: dora-governor-demo
```

You can use the `governor` tag to group these nodes together in a committee.

You will have some nodes DIDs in the form:

did:iota:rms:did_tag1
did:iota:rms:did_tag2
did:iota:rms:did_tag3

You can ask the nodes to create a committee by running the following command:

```bash
dora-storage new-committee --governor governor-tag --nodes did_tag1,did_tag2,did_tag3 
```

For example, for a governor's tag equal to `dora-governor-demo` and nodes DIDs equal to: 
```
did:iota:rms:0x99c7b8faf3732bff32db3364449b0529935ddcb1ccd3689f7008f4d7a039b622
did:iota:rms:0x88a060a7a5c3e657f0ca01624aed9e27d4026856f588e61c3d0294ae0ac02fed
did:iota:rms:0xcda7287931253a7a805911f85da061ba6c8c4bc47bcd95caa1644ca467c56540
```
the command will look like: 
```bash
dora-storage new-committee --governor dora-governor-demo --nodes 0x99c7b8faf3732bff32db3364449b0529935ddcb1ccd3689f7008f4d7a039b622,0x88a060a7a5c3e657f0ca01624aed9e27d4026856f588e61c3d0294ae0ac02fed,0xcda7287931253a7a805911f85da061ba6c8c4bc47bcd95caa1644ca467c56540 
```

In this command, you can omit the `node-url` argument (which is defaulted to `https://api.testnet.shimmer.network`) and the governor argument which is defaulted to `dora-governor-demo` (the governor specified in the provided [docker-compose](docker-compose.yml)). If you specified a different `governor` tag for your nodes, you MUST specify the chosen tag here, otherwise, the nodes won't see the `governor` message.

As soon as the message is received by all the nodes, the DKG will start, and it will be running for a while (a couple of minutes in our tests). You will know this phase is over when the committee generates a committee's DID document and publishes it on the Tangle.

Log example:

```
INFO  dora_storage::demo::node   > committee's DID document has been published
INFO  dora_storage::demo::node   > listening for committee requests on tag: 13b197eba7ff81d5febee8ecbe07f6b0df6c4488121b800b8350798a16893d8c
```

From now on they will listen to the committee's DID tag for requests. The request is a generic set of instructions that will be fully functional when we release the final dOra software. For this demo, the expected behavior is to publish data to the Tangle from a given source and to store data from sources that can be later retrieved. 

STEP 3 - Sending requests
----------------

Requests are sent to the committee using the following command:

```bash
dora-storage request --arg value --arg value --arg value ...
```
The following table offers a brief description of all the arguments that you can pass to the command.

|    Argument    | Required |                                                                                       Description                                                                                       |
|:--------------:|:--------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| committee-tag |    Yes   |                                           the tag where the committee is listening for requests (it is the last part of the committee's DID)                                           |
|    input-uri   |    Yes   | the input location in a uri format, supported values are:  `iota:message:{block_id}`, `literal:string:{data_string}` `storage:local:{storage_id}` and you can also provide any kind of http url |
|   storage-id   |    No    |                                   if this argument is present, data from the input will be stored in the storage using the given {storage_id} as key.                                   |
|       node-url       |    No   | the Stardust Testnet node to use |

As soon as the request is received the committee will start working on it. 
Log example: 

```
INFO  dora_storage::demo::node   > received a request for the committee (block_id: f27379c8d76f87ce52c576b1b36a8288580224d7194fffebbbaf7caac784ea3d)
```

The request will be processed up processed up until completion or failure.
Log example:

```
INFO  dora_storage::demo::node          > request [f27379c8d7] done
```

### Store request

To send a request to store some kind of input you should include the `storage-id` in the request. For example, to store the string `test_string`, using the storage key `test` while using a committee deployed on the IOTA Mainnet, the request would look like this: 

```bash
dora-storage request --committee-tag some_tag --input-uri literal:string:test_string --storage-id test
```

### Get request

To send a request to get some kind of input you should NOT include the `storage-id` in the request. For example to retrieve the string `test_string` previously stored, which was stored using the storage key `test`, the request would look like this: 

```bash
dora-storage request --committee-tag some_tag --input-uri storage:local:test
```

You can also use the "get request" to make the committee work as an oracle. For example by calling this command:

```bash
dora-storage request --committee-tag some_tag --input-uri https://api.coindesk.com/v1/bpi/currentprice.json
```

you will use the input provided by the given API response as data for the committee to publish on the Tangle. At this moment this kind of data should be deterministic, or at least have very limited time-related variance. The url used in this example contains a timestamp with a time resolution of 1 minute, as it is updated every minute, as such, it is very likely that most nodes will get the same "version" of this input. Special behavior for non-deterministic data is still under definition.

The last input-uri which was not discussed is `iota:message:{block_id}`, by using this input uri the selected input will be the payload of the tagged data found at the given id.

STEP 4 - Analyze committee logs
----------------

The committee will provide 2 kinds of outputs:

1) Distributed signature logs: contains information about a specific signature session (like the nodes who didn't participate or provided a wrong signature), it is published by each node and it can be considered a debug/governance type of data. It is signed by each node that provided a correct signature.

2) Committee's task logs: are generated by the committee as a single entity every time a requested task terminates. It contains information such as the result of the operation (Success||Failure), the id of the request that generated the log, and the data if the requested task generates data to be published. It is signed by the committee.

After a "get" request, the requested data can be found inside the "Committee's task log" related to the request. 

These logs are published on the committee's DID tag, and their message-id is found in the local execution log of the nodes. Committee's logs are signed by the committee, but only one node will carry out the publishing operation. As such, in this simple demo, you will find the "Committee's log" message id in the trace logging of the node that will effectively publish.

```
INFO  sign:f27379c8d7                   > node's signature log published (block_id: 0x29e879891746dd8733a54d8f9ccedb5bed6338a8cd70e7bef07f7a6630569551)
INFO  dora_storage::demo::node          > committee's task log for request [f27379c8d7] published (block_id: 0x3ccb2661263fd9ae7c4975f4797c1f969da8d3efcf7c6776a863479b9584fd5b)
```

To verify the signature of Signature logs and Committee's logs you can use respectively the following commands:

```bash
dora-storage verify-log --log log_as_a_json_string
```

```bash
dora-storage verify --committee-log committee_log_as_a_json_string
```

These logs include the DID that contains the public key which the signature must be verified against, hence, no further information is needed for verification.

SAVING NODE AND COMMITTEE STATE
----------------

During the run, each node will save to its docker volume some information. Those information are used to run the demo starting from a previously reached state. 

Data are saved a the following step:
1. Node's keypair creation -> Keypair is saved
2. Node's DID document creation and publication -> Node's DID is saved
3. Distributed Key Generation -> Distributed parameters and peers are saved
4. Committee's DID creation and publication -> Committee's DID is saved

To reset the to run from the start, you have to manually remove the docker volumes linked to the dOra nodes.
