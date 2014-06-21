Socket Ninja
============

Using raw sockets in Go, connect to a host and learn what it can.

Notes:
* This is extremely experimental and will likely leave the local and/or remote sides tcp stack in a mess.
* You need an iptables rule to block kernels outgoing RST packet: iptables -A OUTPUT -d REMOTE_IP -p tcp --tcp-flags RST RST -j DROP
* Needs to run as root (raw sockets).
* This is so experimental, noone will learn anything from the code or the output (yet).

What it will try to learn (currently):
* TCP's initial congestion window

