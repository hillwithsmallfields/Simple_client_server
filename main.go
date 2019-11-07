package main

import (
//ifdef_crypto//	"errors"
	"flag"
	"fmt"
//ifdef_crypto//	"os"
	"strings"

//ifdef_crypto//	"io/ioutil"

//ifdef_crypto//	"crypto/rsa"
//ifdef_crypto//	"golang.org/crypto/ssh" // "crypto/x509"
//ifdef_crypto//	"encoding/pem"

//ifdef_crypto//	"github.com/joho/godotenv"
)

//ifdef_crypto//func readPrivateKey(filename, passphrase string) (*rsa.PrivateKey, error) {
//ifdef_crypto//	// todo: use the passphrase
//ifdef_crypto//	fmt.Fprintf(os.Stderr, "readPrivateKey filename=%s passphrase=%s\n", filename, passphrase)
//ifdef_crypto//	fileContents, err := ioutil.ReadFile(filename)
//ifdef_crypto//	if err != nil {
//ifdef_crypto//		fmt.Fprintf(os.Stderr, "Could not read key file %s\n", filename)
//ifdef_crypto//		return nil, err
//ifdef_crypto//	}
//ifdef_crypto//	fmt.Fprintf(os.Stderr, "file contents are %s\n", fileContents)
//ifdef_crypto//	block, _ := pem.Decode(fileContents)
//ifdef_crypto//	if block == nil {
//ifdef_crypto//		return nil, errors.New("Failed to parse key block")
//ifdef_crypto//	}
//ifdef_crypto//	// key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
//ifdef_crypto//	key, err := ssh.ParseRawPrivateKey(block.Bytes)
//ifdef_crypto//	if err != nil {
//ifdef_crypto//		fmt.Fprintf(os.Stderr, "Failed to parse private key from file %s: error %s\n", filename, err)
//ifdef_crypto//		return nil, err
//ifdef_crypto//	}
//ifdef_crypto//	fmt.Fprintf(os.Stderr, "key is %s\n", key)
//ifdef_crypto//	return key, nil
//ifdef_crypto//}
//ifdef_crypto//
//ifdef_crypto//func readKeysFromFiles(queryKeyFile, queryPassphrase, replyKeyFile, replyPassphrase string) (*rsa.PrivateKey, *rsa.PrivateKey, error) {
//ifdef_crypto//	var queryKey *rsa.PrivateKey
//ifdef_crypto//	var qErr error
//ifdef_crypto//	if queryKeyFile != "" {
//ifdef_crypto//		queryKey, qErr = readPrivateKey(queryKeyFile, queryPassphrase)
//ifdef_crypto//		if qErr != nil {
//ifdef_crypto//			return nil, nil, qErr
//ifdef_crypto//		}
//ifdef_crypto//	}
//ifdef_crypto//	var replyKey *rsa.PrivateKey
//ifdef_crypto//	var rErr error
//ifdef_crypto//	if replyKeyFile != "" {
//ifdef_crypto//		replyKey, rErr = readPrivateKey(replyKeyFile, replyPassphrase)
//ifdef_crypto//		if rErr != nil {
//ifdef_crypto//			return nil, nil, rErr
//ifdef_crypto//		}
//ifdef_crypto//	}
//ifdef_crypto//	return queryKey, replyKey, nil
//ifdef_crypto//}

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
//ifdef_crypto//	queryKeyFile := flag.String("query-key", "querykey", "The key files for decrypting the queries.")
//ifdef_crypto//	replyKeyFile := flag.String("reply-key", "replykey", "The key files for encrypting the replies.")
	verbosePtr := flag.Bool("verbose", false, "Run verbosely")
	flag.Parse()
	data := flag.Args()
//ifdef_crypto//	godotenv.Load()
//ifdef_crypto//	queryPassphrase := os.Getenv("query_passphrase")
//ifdef_crypto//	replyPassphrase := os.Getenv("reply_passphrase")
//ifdef_crypto//	queryKey, replyKey, err := readKeysFromFiles(
//ifdef_crypto//		*queryKeyFile,
//ifdef_crypto//		queryPassphrase,
//ifdef_crypto//		*replyKeyFile,
//ifdef_crypto//		replyPassphrase)
//ifdef_crypto//	if err != nil {
//ifdef_crypto//		fmt.Fprintf(os.Stderr, "Problem reading key files\n")
//ifdef_crypto//	}
//ifdef_crypto//	fmt.Printf("queryPassphrase=%s, replyPassphrase=%s\n", queryPassphrase, replyPassphrase)
	fmt.Printf("runAsServer=%t hostAddress=%s port=%d useTCP=%t\n", *runAsServerPtr, *hostAddressPtr, *portPtr, *useTCPPtr)
//ifdef_crypto//	fmt.Printf("queryKey is %v replykey is %v\n", queryKey, replyKey)

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
//ifdef_crypto//		if queryKey != nil && replyKey != nil {
//ifdef_crypto//			encryptionScheme = 'H'
//ifdef_crypto//		}
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
