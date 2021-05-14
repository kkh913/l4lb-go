// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dropbox/goebpf"
	log "github.com/sirupsen/logrus"
)

var iface = flag.String("iface", "veth0", "Interface to bind XDP program to")
var elf = flag.String("elf", "ebpf_prog/xdp.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "xdp_l4lb", "Name of XDP program (function name)")

const MAX_SERVERS int = 32

type destInfo struct {
	Saddr uint32
	Daddr uint32
	Bytes uint64
	Pkts  uint64
	Dmac  [8]byte
}

var stats [MAX_SERVERS]destInfo

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find servers eBPF map
	servers := bpf.GetMapByName("servers")
	if servers == nil {
		fatalError("eBPF map 'servers' not found")
	}

	// Program name matches function name in xdp.c:
	//      int packet_count(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		fatalError("Program '%s' not found.", *programName)
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	file, err := os.Open("destination_samples/32_destinations.csv")
	if err != nil {
		fatalError("os.Open(): %v", err)
	}
	defer file.Close()

	rdr := csv.NewReader(bufio.NewReader(file))

	rows, err := rdr.ReadAll()
	if err != nil {
		fatalError("rdr.ReadAll(): %v", err)
	}

	buf := &bytes.Buffer{}

	for i, col := range rows {
		dstIP := net.ParseIP(col[0]).To4()
		if dstIP == nil {
			log.Fatal("Invalid IP address")
		}
		macStr := strings.Trim(col[1], " ")
		dstMAC, err := net.ParseMAC(macStr)
		if err != nil {
			log.Fatal(err)
		}

		info := destInfo{Saddr: 0x0A000001, Daddr: binary.LittleEndian.Uint32(dstIP)}
		copy(info.Dmac[:], dstMAC)

		buf.Reset()
		err = binary.Write(buf, binary.LittleEndian, info)
		if err != nil {
			fatalError("binary.Write(): %v", err)
		}

		err = servers.Insert(uint32(i), buf.Bytes())
		if err != nil {
			fatalError("servers.Insert(): %v", err)
		}
	}

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Print stat every second / exit on CTRL+C
	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println()
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			fmt.Print("\033[H\033[2J")
			// Print only first 132 numbers (HOPOPT - SCTP)
			for i := 0; i < MAX_SERVERS; i++ {
				value, err := servers.Lookup(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}

				buf.Reset()
				buf.Write(value)

				info := destInfo{}
				err = binary.Read(buf, binary.LittleEndian, &info)
				if err != nil {
					fatalError("[]bytes to struct destInfo failed: %v", err)
				}

				pps := info.Pkts - stats[i].Pkts

				bw := info.Bytes - stats[i].Bytes
				bps := float32((bw * 8) / 1000000)

				destIP := make([]byte, 4)
				binary.LittleEndian.PutUint32(destIP, info.Daddr)

				ip := fmt.Sprintf("%d.%d.%d.%d", destIP[0], destIP[1], destIP[2], destIP[3])

				fmt.Printf("%-12s %11d pkts ( %10d pps ) %11d Kbytes ( %6.0f Mbits/s )\n",
					ip, info.Pkts, pps, uint64(info.Bytes/1000), bps)

				stats[i] = info
			}
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return

		}
	}
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}
