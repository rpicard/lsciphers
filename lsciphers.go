package main

import (
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "os"
    "sort"
    "sync"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Printf("Usage: %s <host>[:port]\n", os.Args[0])
        os.Exit(1)
    }
    for _, target := range os.Args[1:] {
        ciphers := list(target)
        fmt.Printf("%s:\n", target)
        for _, cipher := range ciphers {
            fmt.Printf("  %s\n", cipher)
        }
        if len(ciphers) == 0 {
            fmt.Println("No ciphers matched.")
        }
    }
}

func list(target string) []string {
    ret := make(chan string, 1000)
    var wg sync.WaitGroup

    wg.Add(1)
    go list_ssl2(target, ret, &wg)

    wg.Add(1)
    go list_ssl3(target, ret, &wg)

    wg.Add(1)
    go list_tls10(target, ret, &wg)

    wg.Add(1)
    go list_tls11(target, ret, &wg)

    wg.Add(1)
    go list_tls12(target, ret, &wg)

    wg.Wait()
    close(ret)

    var ciphers []string
    cipherSet := map[string]bool{}
    for s := range ret {
        if _, ok := cipherSet[s]; !ok {
            cipherSet[s] = true
            ciphers = append(ciphers, s)
        }
    }
    sort.Strings(ciphers)
    return ciphers
}

func list_tls12(target string, ret chan string, wg *sync.WaitGroup) {

    TLS11_HELLO_TEMPLATE := []byte{
        0x16,                       // content type: handshake
        0x03, 0x03,                 // version: tls 1.2
        0x00, 0x2d,                 // length: 46
        0x01,                       // handshake type: client hello
        0x00, 0x00, 0x29,           // length: 42
        0x03, 0x03,                 // version: tls 1.2
        0xde, 0xad, 0xbe, 0xef,     // random: timestamp
        0xde, 0xad, 0xbe, 0xef,     // random: 28 bytes
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0x00,                       // session id length
        0x00, 0x02,                 // cipher suites length
        0x00, 0x00,                 // cipher suites (to be replaced) (location is [46, 47])
        0x01,                       // compression methods length
        0x00,                       // compression methods
    }

    for key, value := range TLS_CIPHERS {

        // create a new copy of the hello from the template
        TLS11_HELLO := make([]byte, len(TLS11_HELLO_TEMPLATE))
        copy(TLS11_HELLO, TLS11_HELLO_TEMPLATE)

        // set the cipher suite we want to check
        cipherBytes := make([]byte, 2)
        binary.BigEndian.PutUint16(cipherBytes, key)
        TLS11_HELLO[46] = cipherBytes[0]
        TLS11_HELLO[47] = cipherBytes[1]

        conn, err := net.Dial("tcp", target)
        if err != nil {
            fmt.Println(err)
            wg.Done()
            return
        }

        conn.Write(TLS11_HELLO)

        contentType := make([]byte, 1)
        io.ReadFull(conn, contentType)
        conn.Close()

        if contentType[0] == byte(0x16) {
            // send the supported cipher back to the channel
            ret <- value
        }

    }

    wg.Done()
    return
}

func list_tls11(target string, ret chan string, wg *sync.WaitGroup) {

    TLS10_HELLO_TEMPLATE := []byte{
        0x16,                       // content type: handshake
        0x03, 0x02,                 // version: tls 1.1
        0x00, 0x2d,                 // length: 46
        0x01,                       // handshake type: client hello
        0x00, 0x00, 0x29,           // length: 42
        0x03, 0x02,                 // version: tls 1.1
        0xde, 0xad, 0xbe, 0xef,     // random: timestamp
        0xde, 0xad, 0xbe, 0xef,     // random: 28 bytes
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0x00,                       // session id length
        0x00, 0x02,                 // cipher suites length
        0x00, 0x00,                 // cipher suites (to be replaced) (location is [46, 47])
        0x01,                       // compression methods length
        0x00,                       // compression methods
    }

    for key, value := range TLS_CIPHERS {

        // create a new copy of the hello from the template
        TLS10_HELLO := make([]byte, len(TLS10_HELLO_TEMPLATE))
        copy(TLS10_HELLO, TLS10_HELLO_TEMPLATE)

        // set the cipher suite we want to check
        cipherBytes := make([]byte, 2)
        binary.BigEndian.PutUint16(cipherBytes, key)
        TLS10_HELLO[46] = cipherBytes[0]
        TLS10_HELLO[47] = cipherBytes[1]

        conn, err := net.Dial("tcp", target)
        if err != nil {
            fmt.Println(err)
            wg.Done()
            return
        }

        conn.Write(TLS10_HELLO)

        contentType := make([]byte, 1)
        io.ReadFull(conn, contentType)
        conn.Close()

        if contentType[0] == byte(0x16) {
            ret <- value
        }

    }

    wg.Done()
    return
}

func list_tls10(target string, ret chan string, wg *sync.WaitGroup) {

    TLS10_HELLO_TEMPLATE := []byte{
        0x16,                       // content type: handshake
        0x03, 0x01,                 // version: tls 1.0
        0x00, 0x2d,                 // length: 46
        0x01,                       // handshake type: client hello
        0x00, 0x00, 0x29,           // length: 42
        0x03, 0x01,                 // version: tls 1.0
        0xde, 0xad, 0xbe, 0xef,     // random: timestamp
        0xde, 0xad, 0xbe, 0xef,     // random: 28 bytes
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0x00,                       // session id length
        0x00, 0x02,                 // cipher suites length
        0x00, 0x00,                 // cipher suites (to be replaced) (location is [46, 47])
        0x01,                       // compression methods length
        0x00,                       // compression methods
    }

    for key, value := range TLS_CIPHERS {

        // create a new copy of the hello from the template
        TLS10_HELLO := make([]byte, len(TLS10_HELLO_TEMPLATE))
        copy(TLS10_HELLO, TLS10_HELLO_TEMPLATE)

        // set the cipher suite we want to check
        cipherBytes := make([]byte, 2)
        binary.BigEndian.PutUint16(cipherBytes, key)
        TLS10_HELLO[46] = cipherBytes[0]
        TLS10_HELLO[47] = cipherBytes[1]

        conn, err := net.Dial("tcp", target)
        if err != nil {
            fmt.Println(err)
            wg.Done()
            return
        }

        conn.Write(TLS10_HELLO)

        contentType := make([]byte, 1)
        io.ReadFull(conn, contentType)
        conn.Close()

        if contentType[0] == byte(0x16) {
            ret <- value
        }
    }

    wg.Done()
    return
}

func list_ssl3(target string, ret chan string, wg *sync.WaitGroup) {

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
        0x00, 0x2d,                 // length: 46
        0x01,                       // handshake type: client hello
        0x00, 0x00, 0x29,           // length: 42
        0x03, 0x00,                 // version: ssl 3.0
        0xde, 0xad, 0xbe, 0xef,     // random: timestamp
        0xde, 0xad, 0xbe, 0xef,     // random: 28 bytes
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0xde, 0xad, 0xbe, 0xef,
        0x00,                       // session id length
        0x00, 0x02,                 // cipher suites length
        0x00, 0x00,                 // cipher suites (to be replaced) (location is [46, 47])
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
        SSL3_HELLO[46] = cipherBytes[0]
        SSL3_HELLO[47] = cipherBytes[1]

        conn, err := net.Dial("tcp", target)
        if err != nil {
            fmt.Println(err)
            wg.Done()
            return
        }

        conn.Write(SSL3_HELLO)

        contentType := make([]byte, 1)
        io.ReadFull(conn, contentType)
        conn.Close()

        if contentType[0] == byte(0x16) {
            ret <- value
        }

    }

    wg.Done()
    return
}

func list_ssl2(target string, ret chan string, wg *sync.WaitGroup) {

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

    conn, err := net.Dial("tcp", target)
    if err != nil {
        fmt.Println(err)
        wg.Done()
        return
    }

    // send the client hello
    conn.Write(SSL2_HELLO)

    // get the length of the server hello
    lengthBytes := make([]byte, 2)
    io.ReadFull(conn, lengthBytes)
    serverHelloLength := ((uint16(lengthBytes[0]) & uint16(0x7f)) << 8) | uint16(lengthBytes[1])

    if serverHelloLength < 1 {
        wg.Done()
        return
    }

    // get the server hello
    serverHello := make([]byte, serverHelloLength)
    io.ReadFull(conn, serverHello)
    conn.Close()

    // [0] - server hello should be 0x04
    if serverHello[0] != 0x04 {
        wg.Done()
        return
    }

    // [1] - session id hit
    // [2] - certificate type

    // [3,4] - ssl version 0x00, 0x02
    if binary.BigEndian.Uint16(serverHello[3:5]) != 0x0002 {
        wg.Done()
        return
    }

    // [5,6] - cert length
    certLength := binary.BigEndian.Uint16(serverHello[5:7])

    // [7,8] - cipher spec length
    cipherSpecLength := binary.BigEndian.Uint16(serverHello[7:9])

    // if no ciphers are supported we can just stop now
    if cipherSpecLength == 0x0000 {
        wg.Done()
        return
    }

    // each cipher is 3 bytes, so cipher spec length % 3 should == 0
    if cipherSpecLength % 3 != 0 {
        wg.Done()
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
        ret <- SSL2_CIPHERS[cipher]

    }

    wg.Done()
    return
}


var TLS_CIPHERS = map[uint16]string{
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
    0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
    0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    0x001A: "TLS_DH_anon_WITH_DES_CBC_SHA",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x001E: "TLS_KRB5_WITH_DES_CBC_SHA",
    0x001F: "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    0x0020: "TLS_KRB5_WITH_RC4_128_SHA",
    0x0021: "TLS_KRB5_WITH_IDEA_CBC_SHA",
    0x0022: "TLS_KRB5_WITH_DES_CBC_MD5",
    0x0023: "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    0x0024: "TLS_KRB5_WITH_RC4_128_MD5",
    0x0025: "TLS_KRB5_WITH_IDEA_CBC_MD5",
    0x0026: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    0x0027: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
    0x0028: "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    0x0029: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    0x002A: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
    0x002B: "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    0x002C: "TLS_PSK_WITH_NULL_SHA",
    0x002D: "TLS_DHE_PSK_WITH_NULL_SHA",
    0x002E: "TLS_RSA_PSK_WITH_NULL_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
    0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0042: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x0043: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0046: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
    0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0085: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x0086: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0089: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    0x008A: "TLS_PSK_WITH_RC4_128_SHA",
    0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x008E: "TLS_DHE_PSK_WITH_RC4_128_SHA",
    0x008F: "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0090: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    0x0091: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    0x0092: "TLS_RSA_PSK_WITH_RC4_128_SHA",
    0x0093: "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    0x0094: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    0x0095: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
    0x0097: "TLS_DH_DSS_WITH_SEED_CBC_SHA",
    0x0098: "TLS_DH_RSA_WITH_SEED_CBC_SHA",
    0x0099: "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    0x009A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    0x009B: "TLS_DH_anon_WITH_SEED_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00A0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
    0x00A1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x00A4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
    0x00A5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
    0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0x00AA: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    0x00AB: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    0x00AC: "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    0x00AD: "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    0x00AE: "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0x00AF: "TLS_PSK_WITH_AES_256_CBC_SHA384",
    0x00B0: "TLS_PSK_WITH_NULL_SHA256",
    0x00B1: "TLS_PSK_WITH_NULL_SHA384",
    0x00B2: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    0x00B3: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    0x00B4: "TLS_DHE_PSK_WITH_NULL_SHA256",
    0x00B5: "TLS_DHE_PSK_WITH_NULL_SHA384",
    0x00B6: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    0x00B7: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    0x00B8: "TLS_RSA_PSK_WITH_NULL_SHA256",
    0x00B9: "TLS_RSA_PSK_WITH_NULL_SHA384",
    0x00BA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BB: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BC: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BD: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BE: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00BF: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    0x00C0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C1: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C2: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C3: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0x00C5: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
    0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
    0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
    0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC01A: "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
    0xC01B: "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC01C: "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
    0xC01D: "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    0xC01E: "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    0xC01F: "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
    0xC020: "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    0xC021: "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    0xC022: "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC033: "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
    0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    0xC037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    0xC038: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    0xC039: "TLS_ECDHE_PSK_WITH_NULL_SHA",
    0xC03A: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
    0xC03B: "TLS_ECDHE_PSK_WITH_NULL_SHA384",
    0xC03C: "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC03D: "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC03E: "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
    0xC03F: "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
    0xC040: "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC041: "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC042: "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
    0xC043: "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
    0xC044: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC045: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC046: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
    0xC047: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
    0xC048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC04A: "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC04B: "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC04C: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04D: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC04E: "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04F: "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC052: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC053: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC054: "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC055: "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC056: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
    0xC057: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
    0xC058: "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
    0xC059: "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
    0xC05A: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
    0xC05B: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
    0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC05E: "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05F: "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC062: "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC063: "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC064: "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC065: "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC066: "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC067: "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC068: "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC069: "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC06A: "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06B: "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC06C: "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06D: "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC06E: "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06F: "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC070: "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC071: "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC074: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC075: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC078: "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC079: "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC07A: "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07B: "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC07C: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07D: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC07E: "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07F: "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC080: "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    0xC081: "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    0xC082: "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    0xC083: "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    0xC084: "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
    0xC085: "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
    0xC086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC088: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC089: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08A: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08B: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08C: "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08D: "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08E: "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08F: "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC090: "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC091: "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC092: "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC093: "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC094: "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC095: "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC096: "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC097: "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC098: "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC099: "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC09A: "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC09B: "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xC0A0: "TLS_RSA_WITH_AES_128_CCM_8",
    0xC0A1: "TLS_RSA_WITH_AES_256_CCM_8",
    0xC0A2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    0xC0A3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    0xC0A4: "TLS_PSK_WITH_AES_128_CCM",
    0xC0A5: "TLS_PSK_WITH_AES_256_CCM",
    0xC0A6: "TLS_DHE_PSK_WITH_AES_128_CCM",
    0xC0A7: "TLS_DHE_PSK_WITH_AES_256_CCM",
    0xC0A8: "TLS_PSK_WITH_AES_128_CCM_8",
    0xC0A9: "TLS_PSK_WITH_AES_256_CCM_8",
    0xC0AA: "TLS_PSK_DHE_WITH_AES_128_CCM_8",
    0xC0AB: "TLS_PSK_DHE_WITH_AES_256_CCM_8",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
}

