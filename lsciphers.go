package main

import "net"
import "fmt"

func make_ssl2_hello(cipher []uint8) []byte {

    x := make([]uint8, 28)

    // MSG-CLIENT-HELLO
    x[0] = uint8(0x01)

    // CLIENT-VERSION-MSB
    x[1] = uint8(0x00)

    // CLIENT-VERSION-LSB
    x[2] = uint8(0x02)

    // CIPHER-SPECS-LENGTH-MSB
    x[3] = uint8(0x00)

    // CIPHER-SPECS-LENGTH-LSB
    x[4] = uint8(0x03)

    // SESSION-ID-LENGTH-MSB
    x[5] = uint8(0x00)

    // SESSION-ID-LENGTH-LSB
    x[6] = uint8(0x00)

    // CHALLENGE-LENGTH-MSB
    x[7] = uint8(0x00)

    // CHALLENGE-LENGTH-LSB
    x[8] = uint8(0x10)

    // CIPHER-SPECS-DATA
    x[9] = cipher[0]
    x[10] = cipher[1]
    x[11] = cipher[2]

    // no SESSION-ID-DATA

    // CHALLENGE-DATA is whatever garbage is at the end

    return x
}


func main() {
    // Read the host:port from ARGV

    // Try connecting with each protocol

    conn, _ := net.Dial("tcp", "duckduckgo.com:443")

    conn.Write(make_ssl2_hello([]uint8{0x01, 0x00, 0x80}))

    response := make([]uint8, 32)
    conn.Read(response)

    fmt.Printf("% X\n", response)

        // Try connecting with each cipher suite

    // Print out which cipher suites work for which protocols
}
