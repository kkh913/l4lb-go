package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

func Example_xdpELF(ifname string) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.WithFields(log.Fields{
			"ifname": ifname,
		}).Fatal("failed to lookup")
	}

	program, err := ioutil.ReadFile(*elf)
	if err != nil {
		log.Fatal("failed to ReadFile")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if err != nil {
		log.Fatal("failed to ebpf.LoadCollectionSpecFromReader")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("failed to ebpf.NewCollection")
	}
	defer coll.Close()

	prog := coll.DetachProgram(*programName)
	if prog == nil {
		log.WithFields(log.Fields{
			"program": *programName,
		}).Fatal("Not found")
	}
	defer prog.Close()

	if err := netlink.LinkSetXdpFd(link, prog.FD()); err != nil {
		log.Fatal("failed LinkSetXdpFd", err)
	}

	servers := coll.DetachMap("servers")
	if servers == nil {
		log.Fatal("BPF map 'servers' not found")
	}
	defer servers.Close()

	file, err := os.Open("destination_samples/32_destinations.csv")
	if err != nil {
		log.Fatal("os.Open()", err)
	}
	defer file.Close()

	rdr := csv.NewReader(bufio.NewReader(file))

	rows, err := rdr.ReadAll()
	if err != nil {
		log.Fatal("rdr.ReadAll()")
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
			log.Fatal("binary.Write()")
		}

		err = servers.Put(uint32(i), buf.Bytes())
		if err != nil {
			log.Fatal("servers.Insert()")
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
				value, err := servers.LookupBytes(uint32(i))
				if err != nil {
					log.Fatal("LookupInt failed", err)
				}

				buf.Reset()
				buf.Write(value)

				info := destInfo{}
				err = binary.Read(buf, binary.LittleEndian, &info)
				if err != nil {
					log.Fatal("[]bytes to struct destInfo failed: %v", err)
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

func main() {
	flag.Parse()
	if *iface == "" {
		log.Fatal("-iface is required.")
	}

	Example_xdpELF(*iface)
}
