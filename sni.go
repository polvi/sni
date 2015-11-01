package sni

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

type bufferedConn struct {
	r    *bufio.Reader
	rout io.Reader
	net.Conn
}

func newBufferedConn(c net.Conn) bufferedConn {
	return bufferedConn{bufio.NewReader(c), nil, c}
}

func (b bufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b bufferedConn) Read(p []byte) (int, error) {
	if b.rout != nil {
		return b.rout.Read(p)
	}
	return b.r.Read(p)
}

func getHello(b []byte) (string, error) {
	rest := b[5:]
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

	if current > len(rest) {
		return "", errors.New("no extensions")
	}

	current += 2

	hostname := ""
	for current < len(rest) && hostname == "" {
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

func getHelloBytes(c bufferedConn) ([]byte, error) {
	b, err := c.Peek(5)
	if err != nil {
		return []byte{}, err
	}

	if b[0] != 0x16 {
		return []byte{}, errors.New("not TLS")
	}

	restLengthBytes := b[3:]
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	return c.Peek(5 + restLength)

}

func getServername(c bufferedConn) (string, []byte, error) {
	all, err := getHelloBytes(c)
	if err != nil {
		return "", nil, err
	}
	name, err := getHello(all)
	if err != nil {
		return "", nil, err
	}
	return name, all, err

}

// Uses SNI to get the name of the server from the connection. Returns the ServerName and a buffered connection that will not have been read off of.
func ServerNameFromConn(c net.Conn) (string, net.Conn, error) {
	bufconn := newBufferedConn(c)
	sn, helloBytes, err := getServername(bufconn)
	if err != nil {
		return "", nil, err
	}
	bufconn.rout = io.MultiReader(bytes.NewBuffer(helloBytes), c)
	return sn, bufconn, nil
}
