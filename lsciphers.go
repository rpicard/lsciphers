package main

import "net"
import "fmt"
import "encoding/binary"

func main() {
    ssl2()
}

func ssl2() {

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

    conn, _ := net.Dial("tcp", "secure.goywam.com:443")

    // send the client hello
    conn.Write(SSL2_HELLO)

    // get the length of the server hello
    lengthBytes := make([]byte, 2)
    conn.Read(lengthBytes)
    serverHelloLength := binary.BigEndian.Uint16(lengthBytes)

    // get the server hello
    serverHello := make([]byte, serverHelloLength)
    conn.Read(serverHello)

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

    // [7,8] - cipher spec length
    cipherSpecLength := binary.BigEndian.Uint16(serverHello[7:9])

    // if no ciphers are supported we can just stop now
    if cipherSpecLength == 0x0000 {
        noSSL2("no ciphers supported")
        return
    }

    // each cipher is 3 bytes, so cipher spec length % 3 should == 0
    if cipherSpecLength % 3 != 0 {
        noSSL2("funky cipher spec length")
        return
    }

}

func getSSL2CipherData(serverHello []byte) {

}

func noSSL2(reason string) {
    fmt.Printf("No SSL2 support:\t%v\n", reason)
    return
}
