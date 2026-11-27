package opera

import (
	"encoding/binary"
	"net"
	"strings"
)

// sniffHost returns the TLS SNI or the HTTP Host of a client's first bytes.
func sniffHost(data []byte) string {
	if host := tlsServerName(data); host != "" {
		return host
	}
	return httpHost(data)
}

func httpHost(data []byte) string {
	text := string(data)
	end := strings.Index(text, "\r\n\r\n")
	if end < 0 {
		end = len(text)
	}
	for _, line := range strings.Split(text[:end], "\r\n")[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			host := strings.TrimSpace(value)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return validHost(host)
		}
	}
	return ""
}

// tlsServerName parses the SNI of a TLS ClientHello in one record.
func tlsServerName(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	record := data[5:]
	if length := int(binary.BigEndian.Uint16(data[3:5])); length < len(record) {
		record = record[:length]
	}
	if len(record) < 4 || record[0] != 0x01 {
		return ""
	}
	hello := record[4:]
	// version(2) random(32)
	if len(hello) < 34 {
		return ""
	}
	position := 34
	skip := func(lengthBytes int) bool {
		if position+lengthBytes > len(hello) {
			return false
		}
		length := 0
		for index := 0; index < lengthBytes; index++ {
			length = length<<8 | int(hello[position+index])
		}
		position += lengthBytes + length
		return position <= len(hello)
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if position+2 > len(hello) {
		return ""
	}
	extensionsEnd := position + 2 + int(binary.BigEndian.Uint16(hello[position:]))
	position += 2
	if extensionsEnd > len(hello) {
		extensionsEnd = len(hello)
	}
	for position+4 <= extensionsEnd {
		kind := binary.BigEndian.Uint16(hello[position:])
		length := int(binary.BigEndian.Uint16(hello[position+2:]))
		position += 4
		if position+length > extensionsEnd {
			return ""
		}
		if kind == 0 && length >= 5 { // server_name
			list := hello[position : position+length]
			nameLength := int(binary.BigEndian.Uint16(list[3:5]))
			if list[2] == 0 && 5+nameLength <= len(list) {
				return validHost(string(list[5 : 5+nameLength]))
			}
			return ""
		}
		position += length
	}
	return ""
}

func validHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\@") {
		return ""
	}
	return host
}
