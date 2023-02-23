dOra a distributed oracle for DLT (storage demo)
====================================

dOra is a distributed oracle built with the cryptographic technique of dkg, which enables the committee paradigm, used for multi-party computation. The system is capable of providing oracle functions in a distributed manner, while also providing more advanced features, such as storage or distributed processing.

This demo is proposed as a proof of concept of the oracular and storage functionality.  

:warning: Disclaimer :warning:
---------------------------------

This demo is not intended to be fully representative of the final dOra system, either functionally or formally. Several possible security holes are present, deliberately overlooked as not of fundamental importance for the purpose of a proof of concept.


Running the demo
----------------

In this demo you can istance a number of nodes through the provided `docker-compose.yml`. Every fresh node will create its own keypair and DID document on the Tangle, and connect to its local storage (a dedicated `minio` istance). To create a committee and send requests, a dedicated CLI app is provided by the very same executable. The nodes will create a committee in response to the `governor` entity, which, in this demo, is represented by a speciel `index` for indexed payloads on the Tangle. Requests will be forwarded to the `committee` using its DID's index, and committee's logs and outputs will also be pulished on the same index. The nodes will communicate using the Tangle, without the necessity of exchanging IPs or anything. This means that you can run multiple nodes from different machines and networks and they will form a `committee` using only the reciprocal DIDs, with some initial input from the `governor`. 

For a detailed set of instruction regarding how to properly run and customize the demo, you can look at the `INSTRUCTIONS.md` file.


Contacts
---------------------------------

If you want to get in touch with us feel free to contact us at <g.pescetelli@teleconsys.it>

