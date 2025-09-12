package main

import (
	"copy-detector/internal/cli"
	"copy-detector/internal/detector"
)

func main() {
	addr, port := cli.Parse()
	detector.Start(addr, port)
}
