# udp-bind-proxy

This implements a proxy to try support online gameplay for a Nintendo
Switch.

## The problem

The Nintendo Switch does not appear to use existing technologies
such as UPnP (Universal Plug and Play) or STUN (Session Traversal
Utilities for NAT) to support online multiplayer gaming. Instead,
they appear to rely on IP network socket semantics that haven't
worked reliably on the Internet since the late 80's.

To work around this, the official Nintendo support documentation
instructs people to configure their home network routers to forward
all connections from the Internet to their Switch. This is undesirable
from a network security point of view, it doesn't support multiple
switches on the same network, and it can make it difficult to provide
externally accessible services on the same router.

### Nintendo Switch Connection Semantics

For multiplayer games, the Switch appears to `bind()` a socket to
a local ephemeral port (ie, a high random port), but leaves it
unconnected (ie, it doesn't call `connect()`). This allows it to
use `sendto()` and `recvfrom()` to exchange UDP packets with any
other IP on the Internet using the one socket.

The expectations the Switch has around receiving packets with this
socket are what cause problems with common NAT implementations.

Firstly, the Switch sends packets from the ephemeral port to a host
on the Internet, but then expects to be able to receive packets
from a random port on the Internet host back to the ephemeral port.

For example, say we have a small home network connected to the
Internet. The IP address given to the Switch is 192.168.1.10, the
router has a public IP of 198.51.100.77, and the Switch is trying
to talk to 203.0.113.12.

The Switch has selected 61185 as it's port for communication, and
then sends a UDP packet to 203.0.113.12 port 2961 (192.168.1.10:61185
-> 203.0.113.12:2961). 203.0.113.12 then appears to pick an ephemeral
port, eg 50920, and sends a reply back to the Switch port 61185
(203.0.113.12:50920 -> 192.168.1.10:61185).

This is incompatible with how NAT and stateful firewalling generally
work. Stateful firewalls and NAT track all the IPs and ports involved
in a connection and only allows replies that exactly match the same
addresses and ports. Using the example above, the only replies a
firewall/NAT device expects when the Switch sends 192.168.1.10:61185
-> 203.0.113.12:2961 is 203.0.113.12:2961 -> 192.168.1.10:61185.
The packet from 203.0.113.12:50920 does not match this state and
is dropped.

Secondly, the Switch expects the same port it selects to be the one
used on the public Internet.

NAT rewrites the IP address of the Switch so it appears to be coming
from the public IP of the router. However, NAT usually also picks
a random source port for the packet. So the 192.168.1.10:61185 ->
203.0.113.12:2961 packet sent by the Switch could rewritten by the
router so it appears to be 198.51.100.77:52811 -> 203.0.113.12:2961.
The Switch seems fine with a router rewriting the source IP, but
expects source port to remain the same, ie, it wants the packet to
appear to be 198.51.100.77:61185 -> 203.0.113.12:2961 on the Internet.
