package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func Parse() (addr string, port int) {
	flag.StringVar(&addr, "address", "", "Multicast group address")
	flag.IntVar(&port, "port", 0, "Multicast group port")
	flag.Parse()

	if addr == "" || port == 0 {
		fmt.Println("Usage: program -address <multicast_ip> -port <port>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if net.ParseIP(addr) == nil {
		fmt.Printf("Invalid IP address: %s\n", addr)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if port <= 0 || port > 65535 {
		fmt.Printf("Invalid port: %d\n", port)
		flag.PrintDefaults()
		os.Exit(1)
	}

	return
}
