package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/server"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

func main() {
	fmt.Println("Logs from your program will appear here!")

	s := server.NewDnsServer(&net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 2053,
	})

	err := s.Listen()
	if err != nil {
		fmt.Println("Failed to listen:", err)
		return
	}

	fmt.Println("Listening on", s.String())
}
