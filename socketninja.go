package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"flag"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, int) {

	// using port 443 just to assist tcpdump ignoring this initial connection
	// usually it should be port 80
	serverAddr, err := net.ResolveTCPAddr("tcp", dstip.String()+":443")
	if err != nil {
		log.Fatalln("Failed to lookup: ", err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.

	if con, err := net.DialTCP("tcp", nil, serverAddr); err == nil {
		if tcpaddr, ok := con.LocalAddr().(*net.TCPAddr); ok {
			// assume the next tcp port is suitable for use on the next connection
			return tcpaddr.IP, tcpaddr.Port + 1
		}
		log.Fatalln("couldn't get here")
	}

	log.Fatalln("could not get local ip: ", err)
	return nil, -1
}

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

func newPacketBuf(sd SrcDst) gopacket.SerializeBuffer {

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

	log.Printf("TCP Options: %s", tcp.Options)

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

// TODO make this random
var globalSeq uint32 = 123

var dataPacketsReceived uint32 = 0

var remoteHost string

// Track next remote sequence to detect retransmissions, we calculate the next
// sequence based on the length of data, as sequence numbers are repeated if
// no extra data was sent (it was just an ack)
var nextRemoteSeq uint32 = 0

// Track the RTT of the original SYN/SYN+ACK transaction
var synAckRTT uint = 0

// Track whether we've started receiving retransmitted packets
var retransmitting bool = false

func init() {

	flag.StringVar(&remoteHost, "host", "di.fm", "Remote host to connect to")
	flag.Parse()

}

func main() {

	log.Printf("Connecting to host: %s\n", remoteHost)

	//dstaddrs, err := net.LookupIP("adam.com.au")
	dstaddrs, err := net.LookupIP(remoteHost)
	if err != nil {
		log.Fatal(err)
	}

	// use the first dst ip
	dstip := dstaddrs[0].To4()

	var dstport layers.TCPPort
	if d, err := strconv.ParseInt("80", 10, 16); err != nil {
		log.Fatal(err)
	} else {
		dstport = layers.TCPPort(d)
	}

	srcip, sport := localIPPort(dstip)
	srcport := layers.TCPPort(sport)
	log.Printf("using srcip: %v", srcip.String())

	// Build the syn packet

	// Note Minimum MTU for ipv4 is 576 bytes, ipv6 1280.
	mss := []byte{0x05, 0xb4} // 1460
	//mss := []byte{0x00, 0xaa} // 170
	//mss := []byte{0x02, 0x40} // 576

	buf := newPacketBuf(SrcDst{
		SrcIP: srcip, DstIP: dstip,
		SrcPort: srcport, DstPort: dstport,
		SYN: true, Seq: globalSeq,
		MSS: mss})

	globalSeq += 1

	//conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	listenSrcip, err := net.ResolveIPAddr("ip4", "192.168.1.11")
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenIP("ip4:tcp", listenSrcip)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("writing request")
	synSentTime := time.Now()
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Fatal(err)
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Println("Readline error")
		log.Fatal(err)
	}

	for {
		b := make([]byte, 4096)
		oob := make([]byte, 4096)

		//log.Println("reading from conn")
		//n, addr, err := conn.ReadFrom(b)
		n, _, _, addr, err := conn.ReadMsgIP(b, oob)

		//log.Fatalf("%#v", b[:n])

		if err != nil {
			log.Println("error reading packet: ", err)
			return
		} else if addr.String() == dstip.String() {
			// Decode a packet
			//packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeIPv4, gopacket.Default)

			//fmt.Println(packet.Dump())

			//fmt.Printf("networkLayer: %#v\n", packet.NetworkLayer())
			//fmt.Printf("transportLayer: %#v\n", packet.TransportLayer())

			//log.Fatalln("sdfsd")

			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

				//ipLayer := packet.Layer(layers.LayerTypeIPv4)
				ipLayer := packet.NetworkLayer()
				ipv4, _ := ipLayer.(*layers.IPv4)

				// fmt.Printf("%#v\n", ipv4)

				tcp, _ := tcpLayer.(*layers.TCP)

				//fmt.Printf("ipLayer %#v\n", ipLayer)
				//fmt.Printf("ipv4 %#v\n", ipv4)
				//fmt.Printf("tcp %#v\n", tcp)

				// I don't know what this exact if statement excludes
				// probably random packets from the internet (or all packets?)?
				if tcp.DstPort == srcport {

					// data legnth is ipv4 header minus tcp header
					length := ipv4.Length - uint16(ipv4.IHL)*4 - uint16(tcp.DataOffset)*4

					log.Printf("Received packet, seq: %d, syn: %v, ack %v, ipv4.length: %d, dataoffset: %d, length: %d, checksum %d\n", tcp.Seq, tcp.SYN, tcp.ACK, ipv4.Length, tcp.DataOffset, length, tcp.Checksum)

					if tcp.SYN && tcp.ACK {
						synAckRTTms := time.Since(synSentTime).Nanoseconds() / 1000 / 1000
						log.Printf("Port %d is OPEN (%d %d) ms: %d\n", dstport, tcp.DstPort, tcp.SrcPort, synAckRTTms)

						nextRemoteSeq = tcp.Seq + 1

						ackPacket(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, length)
						sendHTTP(conn, ipv4.SrcIP, ipv4.DstIP, *tcp)

						_ = time.AfterFunc(time.Duration(synAckRTTms*2)*time.Millisecond, func() {
							// TODO make this a hook
							log.Println("Counted")
						})
					} else if tcp.FIN {
						log.Printf("Received FIN %d packet\n", dstport)
						ackPacket(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, length)
						closeConnection(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, nextRemoteSeq)
					} else if tcp.RST {
						log.Printf("Received RST %d packet\n", dstport)
					} else if tcp.ACK && length == 0 {
						log.Printf("Received ACK %d packet\n", dstport)
					} else {

						// To figure out the initial congestion window, we could just create
						// a map[string]uint8, key on seq and incr each time. Then we can count
						// keys to know how many packets we recieved in initcwnd.
						// After a few moments, we could then ack everthing and handle a
						// connection close.
						//
						// Although this doesn't handle missing packets.

						// Incorrectly detects a retrainsmission when the payload was 0 bytes
						// i.e. just an ack packet.
						// May also have an issue with out of order packets
						if tcp.Seq >= nextRemoteSeq {
							if tcp.Seq > nextRemoteSeq {
								// We could handle this better by buffering the packets
								log.Printf("Received out of order packets, got seq %d, expected %d", tcp.Seq, nextRemoteSeq)
							}

							// Calculate the next sequence number we expect
							nextRemoteSeq := tcp.Seq + 1
							if length > 0 {
								nextRemoteSeq = tcp.Seq + uint32(length)
							}

							// Ack out of order packets, this is wrong, we shouldn't ack until
							// we've received everything in order.
							ackPacket(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, length)

							dataPacketsReceived++
							log.Printf("Received other packet, seq: %d, nextRemote: %d, length: %d, cnt: %d\n", tcp.Seq, nextRemoteSeq, length, dataPacketsReceived)
						} else {
							if !retransmitting {
								retransmitting = true
								log.Printf("Remote end has started retransmitting, we received: %d\n", dataPacketsReceived)
								//closeConnection(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, nextRemoteSeq)
							}
							log.Printf("Discarding retransmitted packet, seq: %d\n", tcp.Seq)
						}
					}
					//return
				}
			}
		} else {
			//log.Printf("Src string %s dont match dst sting %s", addr.String(), dstip.String())
		}
	}

}

func closeConnection(conn *net.IPConn, SrcIP net.IP, DstIP net.IP, tcp layers.TCP, ack uint32) {

	log.Printf("Closing with fin+ack: %d\n", ack)

	// Ack the Syn/Act
	buf := newPacketBuf(SrcDst{
		SrcIP: DstIP, DstIP: SrcIP,
		SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
		SYN: false, ACK: true, FIN: true,
		Seq: globalSeq, Ack: ack})

	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: SrcIP}); err != nil {
		log.Fatal(err)
	}
}

func ackPacket(conn *net.IPConn, SrcIP net.IP, DstIP net.IP, tcp layers.TCP, length uint16) {

	//log.Printf("Received packet from SrcIP %s %d to DstIP %s %d seq %d\n", SrcIP, tcp.SrcPort, DstIP, tcp.DstPort, tcp.Seq)

	// Ack the next sequence number we expect
	ack := tcp.Seq + 1
	if length > 0 {
		ack = tcp.Seq + uint32(length)
	}

	log.Printf("Acking with seq: %d, length: %d ack: %d\n", tcp.Seq, length, ack)

	// Ack the packet
	buf := newPacketBuf(SrcDst{
		SrcIP: DstIP, DstIP: SrcIP,
		SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
		SYN: false, ACK: true,
		Seq: globalSeq, Ack: ack})

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

func sendHTTP(conn *net.IPConn, SrcIP net.IP, DstIP net.IP, tcp layers.TCP) {

	ack := tcp.Seq + 1
	//payload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", remoteHost))
	headers := []string{
		//"GET /resources/css/fonts/NewsGothicMT.css HTTP/1.1", // small
		//"GET /resources/libraries/plugins/jquery.scrollTo-1.4.3.1.js HTTP/1.1", // 3.4kB
		//"GET /resources/libraries/bootstrap/js/bootstrap.min.js HTTP/1.1", // 7.7kB
		"GET /resources/css/v3/vehicles.css HTTP/1.1", // 10.7kB
		"Host: " + remoteHost,
		"Connection: Keep-Alive",
	}
	//payload := []byte(fmt.Sprintf("GET /resources/css/fonts/NewsGothicMT.css HTTP/1.1\r\nHost: %s\r\n\r\n", remoteHost))
	payload := []byte(strings.Join(headers, "\r\n") + "\r\n\r\n")

	// Build actual request packet
	buf := newPacketBuf(SrcDst{
		SrcIP: DstIP, DstIP: SrcIP,
		SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
		SYN: false, ACK: true, PSH: true,
		Seq: globalSeq, Ack: ack,
		Payload: payload,
	})

	globalSeq += uint32(len(payload))

	log.Println("writing sendHTTP")
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: SrcIP}); err != nil {
		log.Fatal(err)
	}
}
