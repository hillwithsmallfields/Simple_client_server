package main

import (
	"flag"
	"fmt"
	"strings"

)

func get_response(query string,
	host string, port int, tcp bool,
	query_key, reply_key string, // *rsa.PrivateKey,
	protocol_version, encryption_scheme, representation_scheme, application_version rune) (string, error) {
	return "placeholder", nil
}

func main() {
	runAsServerPtr := flag.Bool("server", false, "Run as the server.")
	hostAddressPtr := flag.String("host", "127.0.0.1", "The server to handle the query.")
	portPtr := flag.Int("port", 9999, "The port on which to send the query.")
	useTCPPtr := flag.Bool("tcp", false, "Use a TCP connection the server.")
	verbosePtr := flag.Bool("verbose", false, "Run verbosely")
	flag.Parse()
	data := flag.Args()
	fmt.Printf("runAsServer=%t hostAddress=%s port=%d useTCP=%t\n", *runAsServerPtr, *hostAddressPtr, *portPtr, *useTCPPtr)

	if *runAsServerPtr {
		fmt.Println("Running as server")
		// run_servers(args.host, int(args.port),
		//         getter=getter,
		//         files=files,
		//         query_key=query_key,
		//         reply_key=reply_key)
	} else {
		fmt.Println("Running as client")
		text := strings.Join(data, " ")
		encryptionScheme := 'p'
		received, err := get_response(text,
			*hostAddressPtr, *portPtr, *useTCPPtr,
			"", "", // queryKey, replyKey,
			'0', encryptionScheme, 'a', '0')

		if *verbosePtr {
			fmt.Printf("Sent:     %s\n", text)
			if err == nil {
				fmt.Printf("Received: %s\n", received)
			} else {
				fmt.Println("Problem with getting data from server")
			}
		}
	}
}
