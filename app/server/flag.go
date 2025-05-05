package server

type Flag struct {
	flagByte []byte
}
type OPCode uint8

const (
	QUERY    OPCode = 0
	IQUERY   OPCode = 1
	STATUS   OPCode = 2
	RESERVED OPCode = 3
	NOTIFY   OPCode = 4
	UPDATE   OPCode = 5
)

// RCode represents DNS response codes (RCODEs)
type RCode uint16

const (
	RCodeNoError  RCode = 0  // No error condition
	RCodeFormErr  RCode = 1  // Format error
	RCodeServFail RCode = 2  // Server failure
	RCodeNXDomain RCode = 3  // Non-Existent Domain
	RCodeNotImp   RCode = 4  // Not implemented
	RCodeRefused  RCode = 5  // Query refused
	RCodeYXDomain RCode = 6  // Name Exists when it should not
	RCodeYXRRSet  RCode = 7  // RR Set Exists when it should not
	RCodeNXRRSet  RCode = 8  // RR Set that should exist does not
	RCodeNotAuth  RCode = 9  // Server not authoritative for zone / not authorized
	RCodeNotZone  RCode = 10 // Name not contained in zone
)

func NewFlag(bt []byte) *Flag {
	return &Flag{flagByte: bt}
}
func (f Flag) GetQR() bool {
	return f.flagByte[0]&(1<<7) != 0
}
func (f *Flag) SetQR(flag bool) {
	if flag {
		f.flagByte[0] |= (1 << 7)
	} else {
		f.flagByte[0] ^= 0x80
	}
}
func (f Flag) GetOPCode() OPCode {
	return OPCode(f.flagByte[0] >> 4 & 0x07)
}
func (f *Flag) SetOPCode(opcode OPCode) {
	f.flagByte[0] |= (byte(opcode) << 3)
}
func (f Flag) GetAA() bool {
	return f.flagByte[0]&(1<<2) != 0
}
func (f *Flag) SetAA(flag bool) {
	if flag {
		f.flagByte[0] |= (1 << 2)
	} else {
		f.flagByte[0] ^= 0x04
	}
}
func (f Flag) GetTC() bool {
	return f.flagByte[0]&(1<<1) != 0
}
func (f *Flag) SetTC(flag bool) {
	if flag {
		f.flagByte[0] |= (1 << 1)
	} else {
		f.flagByte[0] ^= 0x02
	}
}
func (f Flag) GetRD() bool {
	return f.flagByte[0]&(1<<0) != 0
}
func (f *Flag) SetRD(flag bool) {
	if flag {
		f.flagByte[0] |= (1 << 1)
	} else {
		f.flagByte[0] ^= 0x01
	}
}
func (f Flag) GetRA() bool {
	return f.flagByte[1]&(1<<7) != 0
}
func (f *Flag) SetRA(flag bool) {
	if flag {
		f.flagByte[1] |= (1 << 7)
	} else {
		f.flagByte[1] ^= 0x80
	}
}
func (f Flag) GetZ() byte {
	return f.flagByte[1] >> 4 & 0x7
}
func (f *Flag) SetZ(b byte) {
	f.flagByte[1] &= 0x8f
	f.flagByte[1] |= b << 4
}
func (f Flag) GetRCode() RCode {
	return RCode(f.flagByte[1] & 0x0F)
}
func (f *Flag) SetRCode(rcode RCode) {
	f.flagByte[1] = f.flagByte[1] & (0xF0 + byte(rcode))
}
