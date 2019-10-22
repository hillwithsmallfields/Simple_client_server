package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"io/ioutil"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/joho/godotenv"
)

func readPrivateKey(filename, passphrase string) (*rsa.PrivateKey, error) {
	// todo: use the passphrase
	fileContents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(fileContents)
	if block == nil {
		return nil, errors.New("Failed to parse key block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func readKeysFromFiles(queryKeyFile, queryPassphrase, replyKeyFile, replyPassphrase string) (*rsa.PrivateKey, *rsa.PrivateKey, error) {
	queryKey, qErr := readPrivateKey(queryKeyFile, queryPassphrase)
	if qErr != nil {
		return nil, nil, qErr
	}
	replyKey, rErr := readPrivateKey(replyKeyFile, replyPassphrase)
	if rErr != nil {
		return nil, nil, rErr
	}
	return queryKey, replyKey, nil
}

func get_response(query string,
	host string, port int, tcp bool,
	query_key, reply_key *rsa.PrivateKey,
	protocol_version, encryption_scheme, representation_scheme, application_version rune) (string, error) {
	return "placeholder", nil
}

func main() {
	runAsServerPtr := flag.Bool("server", false, "Run as the server.")
	hostAddressPtr := flag.String("host", "127.0.0.1", "The server to handle the query.")
	portPtr := flag.Int("port", 9999, "The port on which to send the query.")
	useTCPPtr := flag.Bool("tcp", false, "Use a TCP connection the server.")
	queryKeyFile := flag.String("query-key", "", "The key files for decrypting the queries.")
	replyKeyFile := flag.String("reply-key", "", "The key file for encrypting the replies.")
	verbosePtr := flag.Bool("verbose", false, "Run verbosely")
	flag.Parse()
	data := flag.Args()
	godotenv.Load()
	queryPassphrase := os.Getenv("query_passphrase")
	replyPassphrase := os.Getenv("reply_passphrase")
	queryKey, replyKey, err := readKeysFromFiles(
		*queryKeyFile,
		queryPassphrase,
		*replyKeyFile,
		replyPassphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Problem reading key files")
	}
	fmt.Printf("queryPassphrase=%s, replyPassphrase=%s\n", queryPassphrase, replyPassphrase)
	fmt.Printf("runAsServer=%t hostAddress=%s port=%d useTCP=%t\n", *runAsServerPtr, *hostAddressPtr, *portPtr, *useTCPPtr)
	fmt.Printf("queryKey is %v replykey is %v\n", queryKey, replyKey)

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
		if queryKey != nil && replyKey != nil {
			encryptionScheme = 'H'
		}
		received, err := get_response(text,
			*hostAddressPtr, *portPtr, *useTCPPtr,
			queryKey, replyKey,
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
