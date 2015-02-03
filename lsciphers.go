package main

import "net"
import "fmt"
import "encoding/binary"
import "io"

func main() {
    list_ssl2()
    list_ssl3()
}

func list_ssl3() {

    SSL3_CIPHERS := map[uint16]string{
        0x0000: "SSL_NULL_WITH_NULL_NULL",
        0x0001: "SSL_RSA_WITH_NULL_MD5",
        0x0002: "SSL_RSA_WITH_NULL_SHA",
        0x0003: "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004: "SSL_RSA_WITH_RC4_128_MD5",
        0x0005: "SSL_RSA_WITH_RC4_128_SHA",
        0x0006: "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0007: "SSL_RSA_WITH_IDEA_CBC_SHA",
        0x0008: "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0009: "SSL_RSA_WITH_DES_CBC_SHA",
        0x000a: "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        0x000b: "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x000c: "SSL_DH_DSS_WITH_DES_CBC_SHA",
        0x000d: "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        0x000e: "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x000f: "SSL_DH_RSA_WITH_DES_CBC_SHA",
        0x0010: "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0011: "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0012: "SSL_DHE_DSS_WITH_DES_CBC_SHA",
        0x0013: "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        0x0014: "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0015: "SSL_DHE_RSA_WITH_DES_CBC_SHA",
        0x0016: "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0017: "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
        0x0018: "SSL_DH_anon_WITH_RC4_128_MD5",
        0x0019: "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        0x001a: "SSL_DH_anon_WITH_DES_CBC_SHA",
        0x001b: "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
        0x001c: "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
        0x001d: "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
        0x001e: "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA",
    }

    SSL3_HELLO_TEMPLATE := []byte{
        0x16,                       // content type: handshake
        0x03, 0x00,                 // version: ssl 3.0
        0x00, 0x2e,                 // length: 46
        0x01,                       // handshake type: client hello
        0x00, 0x00, 0x2a,           // length: 42
        0x30, 0x00,                 // version: ssl 3.0
        0xde, 0xad, 0xbe, 0xef,     // random: timestamp
        0xde, 0xad, 0xbe, 0xef,     // random: 28 bytes
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0x00,                       // session id length
        0x02,                       // cipher suites length
        0x00, 0x00,                 // cipher suites (to be replaced) (location is [45, 46])
        0x01,                       // compression methods length
        0x00,                       // compression methods
    }

    for key, value := range SSL3_CIPHERS {

        // create a new copy of the hello from the template
        SSL3_HELLO := make([]byte, len(SSL3_HELLO_TEMPLATE))
        copy(SSL3_HELLO, SSL3_HELLO_TEMPLATE)

        // set the cipher suite we want to check
        cipherBytes := make([]byte, 2)
        binary.BigEndian.PutUint16(cipherBytes, key)
        SSL3_HELLO[45] = cipherBytes[0]
        SSL3_HELLO[46] = cipherBytes[1]

        conn, _ := net.Dial("tcp", "google.com:443")

        conn.Write(SSL3_HELLO)

        var _ = value


    }

    return
}

func list_ssl2() {

    SSL2_HELLO := []byte{
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

    SSL2_CIPHERS := map[uint32]string{
        0x010080:     "SSL_CK_RC4_128_WITH_MD5",
        0x020080:     "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        0x030080:     "SSL_CK_RC2_128_CBC_WITH_MD5",
        0x040080:     "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        0x050080:     "SSL_CK_IDEA_128_CBC_WITH_MD5",
        0x060040:     "SSL_CK_DES_64_CBC_WITH_MD5",
        0x0700c0:     "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
    }

    conn, _ := net.Dial("tcp", "mpi.mb.ca:443")

    // send the client hello
    conn.Write(SSL2_HELLO)

    // get the length of the server hello
    lengthBytes := make([]byte, 2)
    io.ReadFull(conn, lengthBytes)
    serverHelloLength := ((uint16(lengthBytes[0]) & uint16(0x7f)) << 8) | uint16(lengthBytes[1])

    // get the server hello
    serverHello := make([]byte, serverHelloLength)
    io.ReadFull(conn, serverHello)

    // [0] - server hello should be 0x04
    if serverHello[0] != 0x04 {
        noSSL2("No server hello")
        return
    }

    // [1] - session id hit
    // [2] - certificate type

    // [3,4] - ssl version 0x00, 0x02
    if binary.BigEndian.Uint16(serverHello[3:5]) != 0x0002 {
        noSSL2("bad version")
        return
    }

    // [5,6] - cert length
    certLength := binary.BigEndian.Uint16(serverHello[5:7])

    // [7,8] - cipher spec length
    cipherSpecLength := binary.BigEndian.Uint16(serverHello[7:9])

    // if no ciphers are supported we can just stop now
    if cipherSpecLength == 0x0000 {
        noSSL2("no ciphers supported")
        //return
    }

    // each cipher is 3 bytes, so cipher spec length % 3 should == 0
    if cipherSpecLength % 3 != 0 {
        noSSL2("funky cipher spec length")
        return
    }

    // [9,10] - connection id length

    // [11: 11+certLength] - certificate data

    // [11+certLength: (11+certLength) + cipherSpecLength] - cipher spec data
    cipherSpecData := serverHello[11 + certLength: 11 + certLength + cipherSpecLength]

    for i := uint16(0); i < cipherSpecLength; i += 3 {
        cipherBytes := make([]byte, 4)
        cipherBytes[1] = cipherSpecData[i]
        cipherBytes[2] = cipherSpecData[i+1]
        cipherBytes[3] = cipherSpecData[i+2]
        cipher := binary.BigEndian.Uint32(cipherBytes)
        fmt.Println(SSL2_CIPHERS[cipher])

    }

}

func noSSL2(reason string) {
    fmt.Printf("No SSL2 support:\t%v\n", reason)
    return
}

