# Remote Attestation

------------


**Remote attestation** *(RA)* is an exceptional property of Intel [SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html), to establish a secure environment between the server and the node (client). Simply in computing, the term attestation means, a procedure to verify the identity of a software and/or hardware. More specifically, *RA* is a medium to verify the interaction between the software and the hardware that has been founded on a trustworthy platform. By following remote attestation flow, a client enclave ensures three things: its identity, its pureness (has not been altered), and a certain piece of code executing in a genuine SGX-enabled CPU. A server sends a remote attestation request to a node and it responds to the request by announcing information about the platform configuration. Node executes the client code while the server runs the server's side code. Both parties are interacting over a network, which is not recognized to be part of any side or secured. The whole operation contains fifteen steps with the server (also called challenger) and the node. It is worth mentioning that *RA* adopts a modified version of the sigma protocol to support Diffie-Hellmann key exchange (DHKE) among the node and the server. The sigma protocol is proof that consists of commitment, challenge, and response.
> Read More: ***A Consensus Protocol for Private Blockchains Using Intel SGX***

