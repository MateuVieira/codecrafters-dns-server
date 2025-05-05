package server

import "encoding/binary"

type Header struct {
	ID      uint16
	Flag    *Flag
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func ParseHeader(buf []byte) *Header {
	id := binary.BigEndian.Uint16(buf[:2])
	flag := NewFlag(buf[2:4])
	qdcount := binary.BigEndian.Uint16(buf[4:6])
	ancount := binary.BigEndian.Uint16(buf[6:8])
	nscount := binary.BigEndian.Uint16(buf[8:10])
	arcount := binary.BigEndian.Uint16(buf[10:12])
	return &Header{
		ID:      id,
		Flag:    flag,
		QDCount: qdcount,
		ANCount: ancount,
		NSCount: nscount,
		ARCount: arcount,
	}
}
func (h Header) Marshal() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[:2], h.ID)
	copy(buf[2:4], h.Flag.flagByte)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)
	return buf
}
