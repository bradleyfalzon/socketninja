package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"code.google.com/p/gopacket/layers"
)

func getDstIP(dstHost string) (net.IP, error) {

	// Get destination IP
	dstaddrs, err := net.LookupIP(dstHost)
	if err != nil {
		return nil, err
	}

	if len(dstaddrs) == 0 {
		return nil, errors.New("Could not resolve host: " + dstHost)
	}

	// use the first destination ip
	return dstaddrs[0].To4(), nil

}

func getDstPort(dstPort string) (layers.TCPPort, error) {

	dstPortHex, err := strconv.ParseInt(dstPort, 10, 16)

	if err != nil {
		return layers.TCPPort(dstPortHex), err
	}

	return layers.TCPPort(dstPortHex), nil

}

func getSrcIPPort(dstIP net.IP) (net.IP, layers.TCPPort, error) {

	// using port 443 just to assist tcpdump ignoring this initial connection
	// usually it should be port 80
	remoteDial := dstIP.String() + ":443"

	serverAddr, err := net.ResolveTCPAddr("tcp", remoteDial)
	if err != nil {
		return net.IP{}, 0, errors.New(fmt.Sprintf("Failed to lookup %s: %s", remoteDial, err))
	}

	// We don't actually use this connection, but we can determine
	// based on our destination ip what source ip we should use.

	con, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		return net.IP{}, 0, errors.New(fmt.Sprintf("Could not connect to remote host %s: %s", remoteDial, err))
	}

	if tcpaddr, ok := con.LocalAddr().(*net.TCPAddr); ok {
		// assume the next tcp port is suitable for use on the next connection
		return tcpaddr.IP, layers.TCPPort(tcpaddr.Port + 1), nil
	}

	return net.IP{}, 0, errors.New(fmt.Sprintf("Unknown error connecting to remote host: %s", remoteDial))

}
