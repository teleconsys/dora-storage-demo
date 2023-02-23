dOra storage demo INSTRUCTIONS
====================================
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
|       governor       |     /     |                                                 the governor's message index where the nodes get instructions for DKG                                                 |
|        storage       |    None   |                                                   the storage type (minio-local is the only one supported right now)                                                  |
|   storage-endpoint   |    None   |                                                               the endpoint where the storage is located                                                               |
|  storage-access-key  |    None   |                                                                     the access key of the storage                                                                     |
|  storage-secret-key  |    None   |                                                                     the secret key of the storage                                                                     |
|        network       | iota-main | the IOTA network to be used (iota-main or iota-dev)                                                                                                                      |
|       node-url       |    None   | the IOTA node to use, if missing the public ones will be used (:warning: provide a node that matches the selected network)                                           |
|    time-resolution   |   20 [s]  | the time resolution used to create the committee  DID Document (needed because the Document has a timestamp which will be different for every node if left unmanaged) |
| signature-sleep-time |   20 [s]  |                        the maximum time the node will wait for its peers' missing partial signatures during a distributed signature operation                        |

It is not mandatory to run every single node at the same time or inside the same machine or docker-compose network. The nodes will initialize themselves by creating their keypair and DID document and then will wait for instructions from the provided governor, that's when the committee will start to cooperate. It is mandatory to set the SAME `governor` index for each of the nodes that you intend to be part of the same committee.

When the nodes are ready to move forward they will print a message which states that they are waiting for instructions from the `governor`.

STEP 2 - Committee creation
----------------

After the first step you are expected to have up and running some nodes (we suggest 3-5 for this demo). Each node will have generated its own DID, which is printed as an output log on the terminal. You can use the `governor` index to group these nodes together in a committee.

You will have some nodes DIDs in the form:

did:iota:didindex1
did:iota:didindex2
did:iota:didindex3

or if you are running your nodes on the devnet: 

did:iota:dev:didindex1
did:iota:dev:didindex2
did:iota:dev:didindex3

You can ask the nodes to create a committee by running the following command:

```bash
dora-storage new-committee --governor governor-index --nodes didindex1,didindex2,didindex3 --network iota-dev
```

In this command, you can omit the `network` argument (which is defaulted to `iota-main`) and the governor argument which is defaulted to `dora-governor-demo` (the governor specified in the provided [docker-compose](docker-compose.yml)). If you specified a different `governor` index for your nodes, you MUST specify the chosen index here, otherwise, the nodes won't see the `governor` message.

As soon as the message is received by all the nodes, the DKG will start, and it will be running for a while (a couple of minutes in our tests). You will know this phase is over when the committee generates a committee's DID document and publishes it on the Tangle.

From now on they will listen to the committee's DID index for requests. The request is a generic set of instructions that will be fully functional when we release the final dOra software. For this demo, the expected behavior is to publish data to the Tangle from a given source and to store data from sources that can be later retrieved. 

STEP 3 - Sending requests
----------------

Requests are sent to the committee using the following command:

```bash
dora-storage request --arg value --arg value --arg value ...
```
The following table offers a brief description of all the arguments that you can pass to the command.

|    Argument    | Required |                                                                                       Description                                                                                       |
|:--------------:|:--------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| committee-index |    Yes   |                                           the index where the committee is listening for requests (it is the last part of the committee's DID)                                           |
|    input-uri   |    Yes   | the input location in a uri format, supported values are:  `iota:message:{msg_id}`, `literal:string:{data_string}` `storage:local:{storage_id}` and you can also provide any kind of http url |
|   storage-id   |    No    |                                   if this argument is present, data from the input will be stored in the storage using the given {storage_id} as key.                                   |
|     network    |    No    |                                                    the network to use for the request (iota-main or iota-dev, defaulted to iota-main)                                                   |


### Store request

To send a request to store some kind of input you should include the `storage-id` in the request. For example, to store the string `test_string`, using the storage key `test` while using a committee deployed on the IOTA Mainnet, the request would look like this: 

```bash
dora-storage request --committee-index some_index --input-uri literal:string:test_string --storage-id test
```

### Get request

To send a request to get some kind of input you should NOT include the `storage-id` in the request. For example to retrieve the string `test_string` previously stored, which was stored using the storage key `test`, the request would look like this: 

```bash
dora-storage request --committee-index some_index --input-uri storage:local:test
```

You can also use the "get request" to make the committee work as an oracle. For example by calling this command:

```bash
dora-storage request --committee-index some_index --input-uri https://api.coindesk.com/v1/bpi/currentprice.json
```

you will use the input provided by the given API response as data for the committee to publish on the Tangle. At this moment this kind of data should be deterministic, or at least have very limited time-related variance. The url used in this example contains a timestamp with a time resolution of 1 minute, as it is updated every minute, as such, it is very likely that most nodes will get the same "version" of this input. Special behavior for non-deterministic data is still under definition.

The last input-uri which was not discussed is `iota:message:{message_id}`, by using this input uri the selected input will be the payload of the IOTA message found at the given id.

STEP 4 - Analyze committee logs
----------------

The committee will provide 2 kinds of outputs:

1) Distributed signature logs: contains information about a specific signature session (like the nodes who didn't participate or provided a wrong signature), it is published by each node and it can be considered a debug/governance type of data. It is signed by each node that provided a correct signature.

2) Committee's task logs: are generated by the committee as a single entity every time a requested task terminates. It contains information such as the result of the operation (Success||Failure), the id of the request that generated the log, and the data if the requested task generates data to be published. It is signed by the committee.

After a "get" request, the requested data can be found inside the "Committee's task log" related to the request. 

These logs are published on the committee's DID index, and their message-id is found in the local execution log of the nodes. Committee's logs are signed by the committee, but only one node will carry out the publishing operation. As such, in this simple demo, you will find the "Committee's log" message id in the trace logging of the node that will effectively publish.

To verify the signature of Signature logs and Committee's logs you can use respectively the following commands:

```bash
dora-storage verify-log --log log_as_a_json_string
```

```bash
dora-storage verify --committee-log committee_log_as_a_json_string
```

These logs include the DID that contains the public key which the signature must be verified against, hence, no further information is needed for verification.