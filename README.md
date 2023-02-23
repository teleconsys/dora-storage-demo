dOra a distributed oracle for DLT (storage demo)
====================================

dOra is a distributed oracle built with the cryptographic technique of DKG and DSS, which enables the committee paradigm, used for multi-party computation. The system is capable of providing oracle functions in a distributed manner, while also providing more advanced features, such as storage or distributed processing.

This demo is proposed as a proof of concept of the oracular and storage functionality.  

Distributed signature consensus
----------------

The committee will provide distributed storage by storing data on each node. When data has to be retrieved, nodes will try to produce a distributed signature of that data without exchanging the value. To produce a valid signature the majority of the nodes must sign the same data (as the partial signature would not be considered valid otherwise). This is because the distributed signature works with a minimum threshold of participants, which was set to be the majority. This means that in an honest working environment, a committee's signature can be produced only if most of the nodes still possess that data, and that signature will be a valid Proof of (data) Conservation for the committee.

The very same logic of a blind signature aggregation consensus can be applied to many kinds of operations, such as the oracular function, execution, etc.

Running the demo
----------------

In this demo, you can instance some nodes through the provided [docker-compose file](docker-compose.yml). Every fresh node will create its keypair and DID document on the Tangle, and connect to its local storage (a dedicated [minio](https://min.io/) instance). 

To create a committee and send requests, a dedicated CLI app is provided by the very same executable. The nodes will create a committee in response to the `governor` entity, which, in this demo, is represented by a special `index` for indexed payloads on the Tangle. Requests will be forwarded to the `committee` using its DID's index, and the committee's logs and outputs will also be published on the same index. 

The nodes will communicate using the Tangle, without the necessity of exchanging IPs or anything. This means that you can run multiple nodes from different machines and networks and they will form a `committee` using only the reciprocal DIDs, with some initial input from the `governor`. 

For a detailed set of instructions regarding how to properly run and customize the demo, you can look at the [INSTRUCTIONS](INSTRUCTIONS.md).

:warning: Disclaimer :warning:
---------------------------------

This demo is not intended to be fully representative of the final dOra system, either functionally or formally. Several possible security holes are present, deliberately overlooked as not of fundamental importance for a proof of concept.


Contacts
---------------------------------

If you want to get in touch with us feel free to contact us at <g.pescetelli@teleconsys.it>