package server

import (
	"encoding/binary"
	"strings"
)

// Question represents a DNS query question section
// DNS Question format:
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     NAME                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     TYPE                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    CLASS                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Question struct {
	Name  string       // Domain name being queried (e.g. "example.com")
	Type  QuestionType // Record type being requested (e.g. A, AAAA, MX)
	Class uint16       // Class of the query (usually 1 for Internet)
}

// QuestionType represents the type of DNS record being requested
type QuestionType uint16

// DNS Question Type constants as defined in RFC 1035
const (
	A     QuestionType = 1  // IPv4 host address
	NS    QuestionType = 2  // Authoritative name server
	MD    QuestionType = 3  // Mail destination (obsolete)
	MF    QuestionType = 4  // Mail forwarder (obsolete)
	CNAME QuestionType = 5  // Canonical name for an alias
	SOA   QuestionType = 6  // Start of a zone of authority
	MB    QuestionType = 7  // Mailbox domain name
	MG    QuestionType = 8  // Mail group member
	MR    QuestionType = 9  // Mail rename domain name
	NULL  QuestionType = 10 // Null resource record
	WKS   QuestionType = 11 // Well known service
	PTR   QuestionType = 12 // Domain name pointer
	MX    QuestionType = 15 // Mail exchange
	TXT   QuestionType = 16 // Text strings
	AAAA  QuestionType = 28 // IPv6 host address
)

// String returns a string representation of the question type
func (qt QuestionType) String() string {
	switch qt {
	case A:
		return "A"
	case NS:
		return "NS"
	case CNAME:
		return "CNAME"
	case MX:
		return "MX"
	case TXT:
		return "TXT"
	case AAAA:
		return "AAAA"
	default:
		return "UNKNOWN"
	}
}

// ParseQuestion parses a DNS question from a byte buffer starting at the given offset
// Returns the parsed Question and the new offset after the question
func ParseQuestion(buf []byte, offset int) (*Question, int) {
	// Parse the domain name
	domainName, newOffset := ParseDomainName(buf, offset)

	// Get the type (2 bytes)
	qType := QuestionType(binary.BigEndian.Uint16(buf[newOffset : newOffset+2]))
	newOffset += 2

	// Get the class (2 bytes, usually 1 for Internet)
	class := binary.BigEndian.Uint16(buf[newOffset : newOffset+2])
	newOffset += 2

	return &Question{
		Name:  domainName,
		Type:  qType,
		Class: class,
	}, newOffset
}

// ParseDomainName parses a domain name from DNS wire format
// DNS domain names are encoded as a series of labels
// Each label starts with a length byte followed by that number of bytes for the label text
// A zero-length label (0 byte) indicates the end of the domain name
// Returns the domain name as a string and the new offset in the buffer
func ParseDomainName(buf []byte, offset int) (string, int) {
	currentOffset := offset
	var labels []string

	for {
		labelLength := int(buf[currentOffset])
		currentOffset++

		if labelLength == 0 {
			break
		}

		// Handle DNS message compression per RFC 1035
		// If the top two bits of the length byte are set (value >= 192),
		// this is a pointer to another location in the message
		if labelLength >= 192 {
			// Remove the top two bits to get the offset value
			// The pointer is 14 bits: 6 from the first byte (after removing top 2 bits) and 8 from the next byte
			pointerOffset := int(((uint16(labelLength) & 0x3F) << 8) | uint16(buf[currentOffset]))
			currentOffset++

			// Recursively parse the domain name from the pointer location
			pointerName, _ := ParseDomainName(buf, pointerOffset)

			// Append the name from the pointer and we're done
			if len(labels) > 0 {
				return strings.Join(labels, ".") + "." + pointerName, currentOffset
			}
			return pointerName, currentOffset
		}

		// Normal case: extract the label and add to our list
		label := string(buf[currentOffset : currentOffset+labelLength])
		labels = append(labels, label)
		currentOffset += labelLength
	}

	// Join all labels with dots to form the domain name
	return strings.Join(labels, "."), currentOffset
}

// EncodeDomainName converts a domain name string (e.g., "example.com")
// to DNS wire format with length-prefixed labels
func EncodeDomainName(domainName string) []byte {
	if domainName == "" || domainName == "." {
		return []byte{0} // Root domain
	}

	// Split the domain name into labels
	labels := strings.Split(domainName, ".")

	// Calculate the total size needed
	size := 0
	for _, label := range labels {
		if len(label) > 0 {
			size += 1 + len(label) // 1 byte for length + label bytes
		}
	}
	size++ // Add 1 for the terminating zero byte

	// Create the buffer
	buf := make([]byte, size)
	offset := 0

	// Encode each label
	for _, label := range labels {
		if len(label) > 0 {
			// Write length byte
			buf[offset] = byte(len(label))
			offset++

			// Write label bytes
			copy(buf[offset:], []byte(label))
			offset += len(label)
		}
	}

	// Terminate with a zero byte
	buf[offset] = 0

	return buf
}

// Marshal serializes the Question into DNS wire format
func (q *Question) Marshal() []byte {
	// Encode the domain name
	nameBuf := EncodeDomainName(q.Name)

	// Allocate buffer for the whole question
	// name + 2 bytes for type + 2 bytes for class
	buf := make([]byte, len(nameBuf)+4)

	// Copy the encoded name
	copy(buf, nameBuf)
	offset := len(nameBuf)

	// Write the type
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(q.Type))
	offset += 2

	// Write the class
	binary.BigEndian.PutUint16(buf[offset:offset+2], q.Class)

	return buf
}
