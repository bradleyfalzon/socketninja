package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/bradleyfalzon/socketninja/libsn"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

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

	srcip, sport := libsn.LocalIPPort(dstip)
	srcport := layers.TCPPort(sport)
	log.Printf("using srcip: %v", srcip.String())

	// Build the syn packet

	// Note Minimum MTU for ipv4 is 576 bytes, ipv6 1280.
	mss := []byte{0x05, 0xb4} // 1460
	//mss := []byte{0x00, 0xaa} // 170
	//mss := []byte{0x02, 0x40} // 576

	buf := libsn.NewPacketBuf(libsn.SrcDst{
		SrcIP: srcip, DstIP: dstip,
		SrcPort: srcport, DstPort: dstport,
		SYN: true, Seq: libsn.GlobalSeq,
		MSS: mss})

	libsn.GlobalSeq += 1

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
		log.Fatalln("SetDeadline Error", err)
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

						libsn.AckPacket(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, length)
						libsn.SendHTTP(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, remoteHost)

						_ = time.AfterFunc(time.Duration(synAckRTTms*2)*time.Millisecond, func() {
							// TODO make this a hook
							log.Println("Counted")
						})
					} else if tcp.FIN {
						log.Printf("Received FIN %d packet\n", dstport)
						libsn.AckPacket(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, length)
						libsn.CloseConnection(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, nextRemoteSeq)
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
							libsn.AckPacket(conn, ipv4.SrcIP, ipv4.DstIP, *tcp, length)

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
