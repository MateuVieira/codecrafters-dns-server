package server

import (
	"fmt"
	"net"
)

type DNSServer struct {
	addr *net.UDPAddr
}

func NewDnsServer(addr *net.UDPAddr) *DNSServer {
	return &DNSServer{
		addr,
	}
}

func (s *DNSServer) String() string {
	return fmt.Sprintf("%s:%d", s.addr.IP, s.addr.Port)
}

func (s *DNSServer) Listen() error {
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		request := ParseRequest(buf[:size])

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		header := Header{
			ID:      request.Header.ID,
			Flag:    NewFlag([]byte{0x00, 0x00}),
			QDCount: request.Header.QDCount,
			ANCount: request.Header.ANCount,
			NSCount: request.Header.NSCount,
			ARCount: request.Header.ARCount,
		}
		header.Flag.SetQR(true)
		fmt.Printf("Header: %v\n", header)

		// Create an empty response
		response := make([]byte, 512)
		responseHeader := header.Marshal()
		copy(response[:12], responseHeader)

		_, err = conn.WriteToUDP(response, source)
		if err != nil {
			return err
		}
	}
}
