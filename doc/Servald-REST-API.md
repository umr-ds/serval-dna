Serval DNA REST API
===================
[Serval Project][], April 2015


[Serval DNA][] is a daemon process (or thread) that runs on every node in a
Serval Mesh network, which acts as the intermediary between applications
running on the same node and the Serval network protocols.

Applications that wish to send or receive data over the Serval mesh network can
use [Serval DNA][]'s **REST API** to access Serval's application-layer
protocols such as [Rhizome][] and [MeshMS][].  To communicate directly using
network-layer protocols, applications must use the [MDP API][MDP] or [MSP
API][MSP].

Protocol and port
-----------------

The REST API is an HTTP 1.0 server that listens on the loopback interface, TCP
port 4110.

The REST API only accepts connections from other processes on the loopback
address (127.0.0.1 in IPv4), to reduce the risk of attacks from remote devices
that snoop network packets or scan for open ports.

Since all communication between the REST API and its clients is confined to the
local host, there is no need for an encrypted protocol like TLS (HTTPS) to
protect against eavesdropping.

Authentication
--------------

The REST API requires that clients authenticate themselves using [Basic
Authentication][].  This reduces the risk from opportunistic attacks on the
HTTP port by malicious applications on the same host that scan for local open
ports to exploit.  Any process wishing to use the REST API must supply valid
authentication credentials (name/password), or will receive a 401 Unauthorized
response.

The name/password pairs accepted by the REST API are [configured][] by the
configuration options of the form:

    api.restful.users.USERNAME.password=PASSWORD

The PASSWORD is a cleartext secret, so the Serval DNA configuration file must
be protected from unauthorised access or modification.


TO BE COMPLETED

-----
**Copyright 2015 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval DNA]:
[Rhizome]:
[MeshMS]:
[MDP]:
[MSP]:
[Basic Authentication]:
[configured]: ./Servald-Configuration.md
