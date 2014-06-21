package libsn

import (
	"log"
	"net"
	"strings"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

// TODO make this random
var GlobalSeq uint32 = 123

type SrcDst struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	SYN     bool
	ACK     bool
	FIN     bool
	RST     bool
	PSH     bool
	Seq     uint32
	Ack     uint32
	Payload []byte
	MSS     []byte
}

func NewPacketBuf(sd SrcDst) gopacket.SerializeBuffer {

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    sd.SrcIP,
		DstIP:    sd.DstIP,
		Protocol: layers.IPProtocolTCP,
	}

	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: sd.SrcPort,
		DstPort: sd.DstPort,
		Seq:     sd.Seq,
		Ack:     sd.Ack,
		SYN:     sd.SYN,
		RST:     sd.RST,
		ACK:     sd.ACK,
		FIN:     sd.FIN,
		PSH:     sd.PSH,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	if len(sd.MSS) != 0 {
		tcp.Options = append(tcp.Options, layers.TCPOption{OptionType: 2, OptionLength: 4, OptionData: sd.MSS})
	}

	if len(tcp.Options) > 0 {
		log.Printf("TCP Options: %s", tcp.Options)
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
	if len(sd.Payload) != 0 {
		/*
			payloadBuffer := gopacket.NewSerializeBuffer()
			payload := gopacket.Payload([]byte{1, 2, 3, 4})

			payload.SerializeTo(payloadBuffer, gopacket.SerializeOptions{})
			err = gopacket.SerializeLayers(buf, opts, tcp, payloadBuffer)
		*/

		log.Printf("Sending packet with %d byte payload", len(sd.Payload))

		payload := gopacket.Payload(sd.Payload)

		err = gopacket.SerializeLayers(buf, opts, tcp, &payload)
	} else {
		err = gopacket.SerializeLayers(buf, opts, tcp)
	}

	if err != nil {
		log.Fatal(err)
	}

	return buf

}

func CloseConnection(conn *net.IPConn, SrcIP net.IP, DstIP net.IP, tcp layers.TCP, ack uint32) {

	log.Printf("Closing with fin+ack: %d\n", ack)

	// Ack the Syn/Act
	buf := NewPacketBuf(SrcDst{
		SrcIP: DstIP, DstIP: SrcIP,
		SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
		SYN: false, ACK: true, FIN: true,
		Seq: GlobalSeq, Ack: ack})

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: SrcIP}); err != nil {
		log.Fatal(err)
	}
}

func AckPacket(conn *net.IPConn, SrcIP net.IP, DstIP net.IP, tcp layers.TCP, length uint16) {

	//log.Printf("Received packet from SrcIP %s %d to DstIP %s %d seq %d\n", SrcIP, tcp.SrcPort, DstIP, tcp.DstPort, tcp.Seq)

	// Ack the next sequence number we expect
	ack := tcp.Seq + 1
	if length > 0 {
		ack = tcp.Seq + uint32(length)
	}

	log.Printf("Acking with seq: %d, length: %d ack: %d\n", tcp.Seq, length, ack)

	// Ack the packet
	buf := NewPacketBuf(SrcDst{
		SrcIP: DstIP, DstIP: SrcIP,
		SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
		SYN: false, ACK: true,
		Seq: GlobalSeq, Ack: ack})

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: SrcIP}); err != nil {
		log.Fatal(err)
	}

	/*
		go func(conn *net.IPConn, buf gopacket.SerializeBuffer, SrcIP net.IP) {
			if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: SrcIP}); err != nil {
				log.Fatal(err)
			}
		}(conn, buf, SrcIP)
	*/

}

func SendHTTP(conn *net.IPConn, SrcIP net.IP, DstIP net.IP, tcp layers.TCP, remoteHost string) {

	ack := tcp.Seq + 1
	//payload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", remoteHost))
	headers := []string{
		"GET /resources/css/fonts/NewsGothicMT.css HTTP/1.1", // small
		//"GET /resources/libraries/plugins/jquery.scrollTo-1.4.3.1.js HTTP/1.1", // 3.4kB
		//"GET /resources/libraries/bootstrap/js/bootstrap.min.js HTTP/1.1", // 7.7kB
		//"GET /resources/css/v3/vehicles.css HTTP/1.1", // 10.7kB
		"Host: " + remoteHost,
		"Connection: Keep-Alive",
	}
	//payload := []byte(fmt.Sprintf("GET /resources/css/fonts/NewsGothicMT.css HTTP/1.1\r\nHost: %s\r\n\r\n", remoteHost))
	payload := []byte(strings.Join(headers, "\r\n") + "\r\n\r\n")

	// Build actual request packet
	buf := NewPacketBuf(SrcDst{
		SrcIP: DstIP, DstIP: SrcIP,
		SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
		SYN: false, ACK: true, PSH: true,
		Seq: GlobalSeq, Ack: ack,
		Payload: payload,
	})

	GlobalSeq += uint32(len(payload))

	log.Println("writing sendHTTP")
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: SrcIP}); err != nil {
		log.Fatal(err)
	}
}

// get the local ip and port based on our destination ip
func LocalIPPort(dstip net.IP) (net.IP, int) {

	// using port 443 just to assist tcpdump ignoring this initial connection
	// usually it should be port 80
	remoteDial := dstip.String() + ":443"

	serverAddr, err := net.ResolveTCPAddr("tcp", remoteDial)
	if err != nil {
		log.Fatalf("Failed to lookup %s: %s", remoteDial, err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.

	con, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		log.Fatalln("Could not get local ip when connecting to host %s: ", remoteDial, err)
	}

	if tcpaddr, ok := con.LocalAddr().(*net.TCPAddr); ok {
		// assume the next tcp port is suitable for use on the next connection
		return tcpaddr.IP, tcpaddr.Port + 1
	}
	log.Fatalf("Couldn't connect to %s", remoteDial)
	return nil, 0

}
