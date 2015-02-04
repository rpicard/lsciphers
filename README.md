# lsciphers

The purpose of this tool is to print out the list of ciphers supported by a host. That's all it does. I don't plan on adding more features. I'm trying to "do one thing well."

Running it looks something like `go run lsciphers.go duckduckgo.com:443`.

`-target` is the only option.

The code is messy and could use some cleaning up. I might do this.

The tool works by sending client hello messages to see what ciphersuites the server supports for each version of the protocol. As far as I know, it checks all of the ciphersuites. I got the list from here: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

Ciphersuites supported in SSL 3.0 have the `SSL_` prefix from [RFC 6101](https://tools.ietf.org/html/rfc6101), so if you want to make sure a server isn't supporting SSL at all you can `grep` the output for `SSL`.

Pull requests and issues are welcome. I do plan on maintaining this tool.
