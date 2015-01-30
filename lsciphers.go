package main

import "net"
import "fmt"


func main() {

    SSL2_HELLO := []uint8{
        0x80, 0x2e,                 // record length
        0x01,                       // client hello
        0x00, 0x02,                 // version
        0x00, 0x15,                 // cipher specs length
        0x00, 0x00,                 // session id length
        0x00, 0x10,                 // challenge length
        0x01, 0x00, 0x80,           // SSL_CK_RC4_128_WITH_MD5
        0x02, 0x00, 0x80,           // SSL_CK_RC4_128_EXPORT40_WITH_MD5
        0x03, 0x00, 0x80,           // SSL_CK_RC2_128_CBC_WITH_MD5
        0x04, 0x00, 0x80,           // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
        0x05, 0x00, 0x80,           // SSL_CK_IDEA_128_CBC_WITH_MD5
        0x06, 0x00, 0x40,           // SSL_CK_DES_64_CBC_WITH_MD5
        0x07, 0x00, 0xc0,           // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        0xde, 0xad, 0xbe, 0xef,     // challenge data
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
    }

    // Read the host:port from ARGV

    // Try connecting with each protocol

    conn, _ := net.Dial("tcp", "secure.goywam.com:443")

    conn.Write(SSL2_HELLO)

    response := make([]uint8, 32)
    conn.Read(response)

    fmt.Printf("% X\n", response)

        // Try connecting with each cipher suite

    // Print out which cipher suites work for which protocols
}
