type SSL2_CLIENT_HELLO struct {
    MSG-CLIENT-HELLO    uint8
    CLIENT-VERSION      uint16
    CIPHER-SPECS-LENGTH uint16
    SESSION-ID-LENGTH   uint16
    CHALLENGE-LENGTH    uint16
    CIPHER-SPECS-DATA   []uint8
    SESSSION-ID-DATA    []uint8
    CHALLENGE-DATA      []uint8
}

// Read the host:port from ARGV

// Try connecting with each protocol

conn, err := net.Dial("tcp", "duckduckgo.com:443")
fmt.Fprintf(conn, 

    // Try connecting with each cipher suite

// Print out which cipher suites work for which protocols
