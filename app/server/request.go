package server

type Request struct {
	Header   *Header
	Question interface{}
	Answer   interface{}
}

func ParseRequest(buf []byte) *Request {
	return &Request{
		Header: ParseHeader(buf[:12]),
	}
}
func (m Request) Marshal() []byte {
	buf := make([]byte, 512)
	copy(buf[:12], m.Header.Marshal())
	return buf
}
