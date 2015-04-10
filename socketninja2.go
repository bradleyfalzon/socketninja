package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

type TCPCxn struct {
	dstHost          string
	srcIP, dstIP     net.IP
	srcPort, dstPort layers.TCPPort
	seqNum, ackNum   uint32
	HttpGet          string
	mss              []byte
	ipconn           *net.IPConn
	lastSendTime     time.Time
}

type TCPPacket struct {
	syn     bool
	ack     bool
	fin     bool
	rst     bool
	psh     bool
	payload []byte
}

type TCPCxnOptions struct {
	DstHost string
	DstPort string
	HttpGet string
	mss     []byte
}

func NewTCPCxn(options TCPCxnOptions) (*TCPCxn, error) {

	tcpcxn := &TCPCxn{dstHost: options.DstHost, HttpGet: options.HttpGet}

	var err error

	tcpcxn.dstIP, err = getDstIP(options.DstHost)
	if err != nil {
		return nil, err
	}

	tcpcxn.dstPort, err = getDstPort(options.DstPort)
	if err != nil {
		return nil, err
	}

	tcpcxn.srcIP, tcpcxn.srcPort, err = getSrcIPPort(tcpcxn.dstIP)
	if err != nil {
		return nil, err
	}

	tcpcxn.mss = options.mss
	if len(options.mss) == 0 {
		// Note Minimum MTU for ipv4 is 576 bytes, ipv6 1280.
		tcpcxn.mss = []byte{0x05, 0xb4} // 1460
		//tcpcxn.mss = []byte{0x00, 0xaa} // 170
		//tcpcxn.mss = []byte{0x02, 0x40} // 576
	}

	// Being lazy and only using 2^31 so I don't need to manage my sequence
	// numbers wrapping.
	rand.Seed(time.Now().UnixNano())
	tcpcxn.seqNum = uint32(rand.Intn(2147483647) + 1)

	// Create a raw socket

	listenIPAddr, err := net.ResolveIPAddr("ip4", tcpcxn.srcIP.String())
	if err != nil {
		return nil, err
	}
	tcpcxn.ipconn, err = net.ListenIP("ip4:tcp", listenIPAddr)
	if err != nil {
		return nil, err
	}

	// Set deadline so we don't wait forever.
	if err := tcpcxn.ipconn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	return tcpcxn, nil
}

func (cxn *TCPCxn) sendPacket(packet TCPPacket) error {

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    cxn.srcIP,
		DstIP:    cxn.dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: cxn.srcPort,
		DstPort: cxn.dstPort,
		Seq:     cxn.seqNum,
		Ack:     cxn.ackNum,
		SYN:     packet.syn,
		RST:     packet.rst,
		ACK:     packet.ack,
		FIN:     packet.fin,
		PSH:     packet.psh,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	if packet.syn && len(cxn.mss) != 0 {
		tcp.Options = append(tcp.Options, layers.TCPOption{OptionType: 2, OptionLength: 4, OptionData: cxn.mss})
	}

	if len(tcp.Options) > 0 {
		log.Printf("TCP Options: %#v", tcp.Options)
	}

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	var err error
	if len(packet.payload) != 0 {
		log.Printf("Sending packet with %d byte payload", len(packet.payload))

		payload := gopacket.Payload(packet.payload)
		err = gopacket.SerializeLayers(buf, opts, tcp, &payload)
		cxn.seqNum += uint32(len(packet.payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, tcp)
		cxn.seqNum += 1
	}

	if err != nil {
		return err
	}

	cxn.lastSendTime = time.Now()

	_, err = cxn.ipconn.WriteTo(buf.Bytes(), &net.IPAddr{IP: cxn.dstIP})
	if err != nil {
		return err
	}

	return nil

}

func (cxn *TCPCxn) listen() error {

	//receiveBuffer := make(map[uint32]*layers.TCP)

	for {
		b := make([]byte, 4096)
		oob := make([]byte, 4096)

		//log.Println("reading from conn")
		//n, addr, err := conn.ReadFrom(b)
		n, _, _, addr, err := cxn.ipconn.ReadMsgIP(b, oob)

		if err != nil {
			return errors.New(fmt.Sprintf("Error reading packet: ", err))
		}

		if addr.String() != cxn.dstIP.String() {
			// Packet did not come from the server
			continue
		}

		packet := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.Default)

		// Get the TCP layer from this packet
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer == nil {
			log.Println("Could not find tcp layer, icmp?")
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		ipLayer := packet.NetworkLayer()
		ipv4, _ := ipLayer.(*layers.IPv4)

		if tcp.DstPort != cxn.srcPort {
			// Exclude packets not related to this connection (correct ip, wrong port)
			continue
		}

		length := ipv4.Length - uint16(ipv4.IHL)*4 - uint16(tcp.DataOffset)*4

		log.Printf("Received packet, seq: %d, syn: %v, ack %v, ipv4.length: %d, dataoffset: %d, length: %d, checksum %d\n", tcp.Seq, tcp.SYN, tcp.ACK, ipv4.Length, tcp.DataOffset, length, tcp.Checksum)

	}

}

func (cxn *TCPCxn) Connect() error {
	log.Printf("Connecting to host: %s (ip:%s)", cxn.dstHost, cxn.dstIP)

	err := cxn.sendPacket(TCPPacket{syn: true})

	if err != nil {
		return err
	}

	err = cxn.listen()

	return nil

}

func main() {

	options := TCPCxnOptions{
		DstHost: "holden.com.au", DstPort: "80",
		HttpGet: "/something.html",
	}

	cxn, err := NewTCPCxn(options)

	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("%#v", cxn)

	cxn.Connect()

}
