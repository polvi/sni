package sni

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

var hello = []byte{22, 3, 1, 0, 135, 1, 0, 0, 131, 3, 3, 48, 53, 69, 203, 240, 58, 77, 56, 159, 42, 153, 251, 106, 51, 38, 204, 75, 107, 173, 175, 235, 47, 66, 133, 56, 177, 148, 100, 25, 71, 144, 144, 0, 0, 26, 192, 47, 192, 43, 192, 17, 192, 7, 192, 19, 192, 9, 192, 20, 192, 10, 0, 5, 0, 47, 0, 53, 192, 18, 0, 10, 1, 0, 0, 64, 0, 0, 0, 14, 0, 12, 0, 0, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 10, 0, 8, 0, 6, 0, 23, 0, 24, 0, 25, 0, 11, 0, 2, 1, 0, 0, 13, 0, 10, 0, 8, 4, 1, 4, 3, 2, 1, 2, 3, 255, 1, 0, 1, 0}

func TestSNI(t *testing.T) {
	ready := make(chan bool)
	go func() {
		l, err := net.Listen("tcp", ":3000")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		ready <- true
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		name, _, err := ServerNameFromConn(conn)
		if err != nil {
			t.Fatal(err)
		}
		if name != "localhost" {
			t.Fatalf("expected %q got %q", "localhost", name)
		}
		return
	}()
	<-ready
	_, err := tls.Dial("tcp", "localhost:3000", nil)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
}

func TestGetHello(t *testing.T) {
	name, err := getHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	if name != "localhost" {
		t.Fatalf("expected %q got %q", "localhost", name)
	}
}

func BenchmarkGetHello(b *testing.B) {
	for i := 0; i < b.N; i++ {
		getHello(hello)
	}
}
