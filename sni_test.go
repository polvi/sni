package sni

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
)

// this is a hello packet with localhost encoded in the SNI field
var hello = []byte{22, 3, 1, 0, 135, 1, 0, 0, 131, 3, 3, 48, 53, 69, 203, 240, 58, 77, 56, 159, 42, 153, 251, 106, 51, 38, 204, 75, 107, 173, 175, 235, 47, 66, 133, 56, 177, 148, 100, 25, 71, 144, 144, 0, 0, 26, 192, 47, 192, 43, 192, 17, 192, 7, 192, 19, 192, 9, 192, 20, 192, 10, 0, 5, 0, 47, 0, 53, 192, 18, 0, 10, 1, 0, 0, 64, 0, 0, 0, 14, 0, 12, 0, 0, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 0, 5, 0, 5, 1, 0, 0, 0, 0, 0, 10, 0, 8, 0, 6, 0, 23, 0, 24, 0, 25, 0, 11, 0, 2, 1, 0, 0, 13, 0, 10, 0, 8, 4, 1, 4, 3, 2, 1, 2, 3, 255, 1, 0, 1, 0}

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
`

var rsaKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA PRIVATE KEY-----
`

func TestSNI(t *testing.T) {
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		l, err := net.Listen("tcp", ":3000")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		wg.Done()
		wg.Add(1)
		defer wg.Done()
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
	wg.Wait()
	_, err := tls.Dial("tcp", "localhost:3000", nil)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestBuffConn(t *testing.T) {
	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	proxyReady := make(chan bool)
	tlsReady := make(chan bool)
	dialDone := make(chan bool)
	testData := []byte("foo")
	go func() {
		<-proxyReady
		<-tlsReady
		defer func() { dialDone <- true }()
		conn, err := tls.Dial("tcp", "localhost:4443", &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		b := make([]byte, len(testData))
		_, err = conn.Read(b)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if bytes.Compare(b, testData) != 0 {
			t.Fatal("expected %q, got %q", "foo", b)
		}
	}()
	go func() {
		l, err := net.Listen("tcp", ":4443")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		proxyReady <- true

		for {
			conn, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			_, bufconn, err := ServerNameFromConn(conn)
			if err != nil {
				t.Fatal(err)
			}

			// dial proxy
			out, err := net.Dial("tcp", "localhost:4444")
			if err != nil {
				t.Fatal(err)
			}
			// now use the buffered conn
			// tls connection above should fail if conn is bad
			go io.Copy(out, bufconn)
			go io.Copy(bufconn, out)
		}
	}()
	go func() {
		l, err := tls.Listen("tcp", ":4444", &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			fmt.Println("err", err)
			t.Fatal(err)
		}
		defer l.Close()
		tlsReady <- true
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write(testData)
	}()
	<-dialDone
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
