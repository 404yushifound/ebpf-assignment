package main

import (
	"flag"
	"fmt"
)

type Packet struct {
	SrcPort    int
	DstPort    int
	Process    string
}

func main() {
	// Flags: user configurable port + process
	port := flag.Int("port", 4040, "Port to drop/allow")
	process := flag.String("process", "myprocess", "Process name to filter")
	flag.Parse()

	// Simulated packets
	packets := []Packet{
		{1234, 4040, "chrome"},
		{2345, 80, "firefox"},
		{3456, 4040, "myprocess"},
		{4567, 22, "myprocess"},
		{5678, 8080, "randomproc"},
	}

	fmt.Printf("Simulating eBPF packet filter...\n")
	fmt.Printf("Target Port = %d, Target Process = %s\n\n", *port, *process)

	for _, p := range packets {
		// Problem 1: Drop TCP packets on port (default: 4040)
		if p.DstPort == *port {
			fmt.Printf("Dropped packet from %s [%d -> %d] (matches port)\n", p.Process, p.SrcPort, p.DstPort)
			continue
		}

		// Problem 2: Drop all traffic for given process, except port 4040
		if p.Process == *process && p.DstPort != 4040 {
			fmt.Printf("Dropped packet from %s [%d -> %d] (process restricted)\n", p.Process, p.SrcPort, p.DstPort)
			continue
		}

		// Otherwise allow
		fmt.Printf("Allowed packet from %s [%d -> %d]\n", p.Process, p.SrcPort, p.DstPort)
	}
}
