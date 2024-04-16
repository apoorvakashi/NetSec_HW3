package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keySize    = 32 // 256-bit key for AES-256
	iterations = 4096
	logFile    = "log.txt"
)

func main() {
	listenMode := flag.Bool("l", false, "Reverse-proxy mode")
	keyFile := flag.String("k", "", "File containing the passphrase")
	flag.Parse()

	if *keyFile == "" {
		customLog.Fatalf("Please provide a password file using -k option")
	}

	passphrase, err := readPassphrase(*keyFile)
	if err != nil {
		customLog.Fatalf("Error reading passphrase: %v", err)
	}

	if *listenMode {
		listenPort := flag.Arg(0)
		destination := flag.Arg(1)
		port := flag.Arg(2)
		if listenPort == "" || destination == "" || port == "" {
			customLog.Fatalf("Usage: go run jumproxy.go [-l listenport] -k pwdfile destination port")
		}
		runReverseProxy(passphrase, listenPort, destination, port)
	} else {
		destination := flag.Arg(0)
		port := flag.Arg(1)
		if destination == "" || port == "" {
			customLog.Fatalf("Usage: go run jumproxy.go  -k pwdfile destination port")
		}
		runClient(passphrase, destination, port)
	}
}

func readPassphrase(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := info.Size()
	if size > (1 << 20) { // Limit file size to 1MB
		return nil, fmt.Errorf("file size exceeds limit")
	}

	passphrase := make([]byte, size)
	_, err = f.Read(passphrase)
	if err != nil {
		return nil, err
	}

	return passphrase, nil
}

func deriveKey(passphrase []byte, salt []byte) []byte {
	return pbkdf2.Key(passphrase, salt, iterations, keySize, sha256.New)
}

func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// customLog.Printf("Encryption - Nonce: %v\n", nonce)

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// customLog.Printf("Encryption - Ciphertext: %v\n", ciphertext)
	// ciphertext = append(nonce, ciphertext...)

	return append(nonce, ciphertext...), nil
}

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()

	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertxt := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// customLog.Printf("Decryption - Nonce: %v\n", nonce)
	// customLog.Printf("Decryption - Ciphertext: %v\n", cipher)

	plaintext, err := aesGCM.Open(nil, nonce, ciphertxt, nil)

	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func runClient(passphrase []byte, destination string, port string) {
	conn, err := net.Dial("tcp", net.JoinHostPort(destination, port))
	if err != nil {
		customLog.Fatalf("Error connecting to server: %v", err)
	}
	defer conn.Close()

	key := deriveKey(passphrase, []byte("thisisthesalt"))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		reader := bufio.NewReader(conn)
		for {
			lenBuf := make([]byte, 4)
			_, err := io.ReadFull(reader, lenBuf)
			if err != nil {
				if err != io.EOF {
					customLog.Fatalf("Error reading buffer size from connection: %v", err)
				}
				break
			}
			length := binary.BigEndian.Uint32(lenBuf)

			// customLog.Printf("Client receiving ciphertext: %x", ciphertext)
			ciphertext := make([]byte, length)

			_, err = io.ReadFull(reader, ciphertext)
			if err != nil {
				customLog.Fatalf("Error reading encrypted  data: %v", err)
			}

			plaintext, err := decrypt(key, ciphertext)

			if err != nil {
				customLog.Fatalf("Error decrypting data: %v", err)
			}
			os.Stdout.Write(plaintext)
		}
	}()

	go func() {
		defer wg.Done()
		writer := bufio.NewWriter(conn)
		buffer := make([]byte, 4096)

		for {
			n, err := os.Stdin.Read(buffer)
			if err != nil {
				if err != io.EOF {
					customLog.Fatalf("Error reading from stdin: %v", err)
				}
				break
			}

			ciphertext, err := encrypt(key, buffer[:n])
			if err != nil {
				customLog.Fatalf("Error encrypting data: %v", err)
			}

			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))

			encryptedMsg := append(lenBuf, ciphertext...)
			// customLog.Printf("Length : %d", len(ciphertext))

			_, err = writer.Write(encryptedMsg)
			if err != nil {
				customLog.Fatalf("Error writing to connection: %v", err)
			}

			// _, err = writer.Write(ciphertext)
			// customLog.Printf("Client sending ciphertext: %x", ciphertext)

			if err != nil {
				customLog.Fatalf("Error writing to connection: %v", err)
			}
			writer.Flush()

		}
	}()

	wg.Wait()
}

func runReverseProxy(passphrase []byte, listenPort string, destination string, port string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		customLog.Fatalf("Error starting listener: %v", err)
	}
	defer ln.Close()

	customLog.Printf("Reverse proxy listening on port %s\n", listenPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			customLog.Fatalf("Error accepting connection: %v", err)
		}
		customLog.Printf("Connection accepted : %s", conn.RemoteAddr().String())
		go handleConnection(conn, passphrase, destination, port)
	}
}

func handleConnection(conn net.Conn, passphrase []byte, destination string, port string) {
	defer conn.Close()

	key := deriveKey(passphrase, []byte("thisisthesalt"))

	destinationConn, err := net.Dial("tcp", net.JoinHostPort(destination, port))
	if err != nil {
		customLog.Fatalf("Error connecting to client: %v", err)
	}
	defer destinationConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		reader := bufio.NewReader(conn)
		for {
			lenBuf := make([]byte, 4)
			_, err := io.ReadFull(reader, lenBuf)
			if err != nil {
				if err != io.EOF {
					customLog.Fatalf("Error reading buffer len from client connection: %v", err)
				}
				break
			}
			length := binary.BigEndian.Uint32(lenBuf)
			// customLog.Printf("Length: %d", int(length))

			// customLog.Printf("Server receiving ciphertext: %x", ciphertext)
			ciphertext := make([]byte, length)
			_, err = io.ReadFull(reader, ciphertext)
			if err != nil {
				customLog.Fatalf("Error reading ciphertext from client: %v", err)
			}

			plaintext, err := decrypt(key, ciphertext)

			if err != nil {
				customLog.Fatalf("Error decrypting data from client: %v", err)
			}
			_, err = destinationConn.Write(plaintext)
			if err != nil {
				customLog.Fatalf("Error writing to destination connection: %v", err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		writer := bufio.NewWriter(conn)
		buffer := make([]byte, 4096)
		for {

			n, err := destinationConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					customLog.Fatalf("Error reading from destination connection: %v", err)
				}
				break
			}

			ciphertext, err := encrypt(key, buffer[:n])
			if err != nil {
				customLog.Fatalf("Error encrypting data for client: %v", err)
			}

			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))

			encryptedMsg := append(lenBuf, ciphertext...)

			_, err = writer.Write(encryptedMsg)

			// _, err = writer.Write(lenBuf)
			if err != nil {
				customLog.Fatalf("Error writing to client connection: %v", err)
			}

			writer.Flush()
		}
		// }
	}()

	wg.Wait()
}

var customLog = log.New(createLogFile(), "", log.LstdFlags)

func createLogFile() *os.File {
	file, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	return file
}
