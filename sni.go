package sni

import (
	"bufio"
	"errors"
	"net"
)

type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func newBufferedConn(c net.Conn) bufferedConn {
	return bufferedConn{bufio.NewReader(c), c}
}

func (b bufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func getServername(c bufferedConn) (string, error) {
	b, err := c.Peek(5)
	if err != nil {
		return "", err
	}

	if b[0] != 0x16 {
		return "", errors.New("not TLS")
	}

	restLengthBytes := b[3:]
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	all, err := c.Peek(5 + restLength)
	if err != nil {
		return "", err
	}

	rest := all[5:]
	current := 0
	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		return "", errors.New("Not a ClientHello")
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		return "", errors.New("no extensions")
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {

			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current += 1
			if nameType != 0 {
				return "", errors.New("Not a hostname")
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		return "", errors.New("No hostname")
	}
	return hostname, nil
}

// Uses SNI to get the name of the server from the connection. Returns the ServerName and a buffered connection that will not have been read off of.
func ServerNameFromConn(c net.Conn) (string, net.Conn, error) {
	bufconn := newBufferedConn(c)
	sn, err := getServername(bufconn)
	if err != nil {
		return "", nil, err
	}
	return sn, bufconn, nil
}
