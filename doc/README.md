Serval DNA Technical Documentation
----------------------------------
[Serval Project][], May 2014

This directory contains [technical documents][] that accompany the [Serval
DNA][] component of the [Serval mesh network][].

 * [Building Serval DNA](../INSTALL.md) has instructions to build a native
   Serval DNA executable.

 * [Testing Serval DNA](./Testing.md) describes the Serval DNA test scripts and
   the test framework.

 * [Configuring Serval DNA](./Servald-Configuration.md) describes the
   persistent configuration system and its command-line API, the built-in
   system file paths, daemon instances and basic network configuration.

 * [MDP Packet Filtering](./Mesh-Packet-Filtering.md) describes the
   configuration options and rules file syntax for filtering incoming and
   outgoing MDP packets.

 * [Tunnelling](./Tunnelling.md) describes how to tunnel IP over the Serval
   mesh network.

 * [Serval DNA on OpenWRT](./OpenWRT.md) describes how to build and install
   Serval DNA packages for the OpenWRT platform.

 * [Serval DNA OpenBTS support](./OpenBTS.md) describes how Serval DNA has been
   integrated with the Commotion Wireless OpenBTS mobile telephony platform.

 * [Mesh Datagram Protocol (MDP)](./Mesh-Datagram-Protocol.md) describes the
   fundamental mesh protocol used in Serval Mesh networks and its C programming
   API.

 * [Mesh Stream Protocol (MSP)](./Mesh-Stream-Protocol.md) describes a reliable
   message stream protocol used in Serval Mesh networks and its C programming
   API.

 * [Serval DNA REST API](./Servald-REST-API.md) describes the HTTP REST API
   that applications can use to access Serval's application-layer protocols
   such as Rhizome and MeshMS.

 * [Cooee](./Cooee.md) describes the protocol used for discovering services
   available on nearby (reachable) mesh network nodes.

 * [Serval Infrastructure](./Serval-Infrastructure.md) contains notes on plans
   for how a Serval mesh network can use the Internet to increase its reach and
   usefulness.

-----
**Copyright 2014 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
This document is available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[Serval DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servaldna:
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[technical documents]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:dev:techdoc
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
