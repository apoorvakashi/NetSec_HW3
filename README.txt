USAGE

Command to run Server side proxy
go run jumproxy.go -k pwdfile -l listen_port server_address server_port

Example:
go run jumproxy.go -k pwd.txt -l 1234 localhost 22
    -k - file containing passphrase,
    -l - to run server side proxy. Server listens on port 1234,
     localhost 22 - is the address and port of the service we want to forward traffic to
    

Command to run Client side proxy
go run jumproxy.go -k pwdfile server_address proxy_listening_port

Example:
go run jumproxy.go -k pwd.txt 192.168.204.128 1234
    -k - file containing passphrase,
    192.168.204.128 - the adress of the server,
     1234 - the port the proxy is listening to
   

=> nc USE CASE: securing remote netcat server
server> nc -l -p 2222
server> go run jumproxy -k pwd.txt -l 1234 localhost 2222
client> go run jumproxy -k pwd.txt 192.168.204.128 1234

=> ssh USE CASE: securing remote SSH server
server> go run jumproxy.go -k pwd.txt -l 2222 localhost 22
client> ssh -o "ProxyCommand go run jumproxy.go -k pwd.txt 192.168.204.129 2222" 192.168.204.129


FUNCTIONING:


Encryption and Decryption (encrypt and decrypt functions):

    Encrypts and decrypts data using AES-256 in GCM mode.
    Generates a random nonce for each encryption.
    Concatenates the nonce with the ciphertext for decryption.

Client Mode (runClient function):

    Connects to a specified destination and port.
    Runs two goroutines:
        One for reading from os.Stdin, encrypting the data, and sending it to the destination.
        Another for reading from the connection, decrypting the data, and writing it to os.Stdout.

Reverse Proxy Mode (runReverseProxy function):

    Listens for incoming connections on a specified port.
    For each accepted connection:
        Connects to the specified destination and port.
        Runs two goroutines:
            One for reading from the client connection, decrypting the data, and sending it to the destination.
            Another for reading from the destination connection, encrypting the data, and sending it to the client.

Logging:

    Logs are written to a file named log.txt.
    A custom logger is created to direct logs to this file.


IMPLEMENTATION DETAILS

Encryption
----------

The proxy uses AES in GCM mode for encyrption (providing confidentiality, integrity and authenticiy). The 32 bit key used during encryption and decryption is derived using PBKDF2 from a password which is provided on both the server and the client side proxies, a salt (hardcoded) , sha256.New (SHA-256) hash function and 4096 number of iterations of the hash function application.

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
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

The client reads data from os.Stdin in chunks using a buffer (buffer with a size of 4096 bytes).

buffer := make([]byte, 4096)

After reading a chunk of data, it encrypts the data using AES-256 in GCM mode.
The encrypted data is then sent over the network in chunks.
Each encrypted chunk includes a 4-byte header specifying the length of the ciphertext followed by the ciphertext itself.

lenBuf := make([]byte, 4)
binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))

encryptedMsg := append(lenBuf, ciphertext...)
_, err = writer.Write(encryptedMsg)

Decryption
----------

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
	plaintext, err := aesGCM.Open(nil, nonce, ciphertxt, nil)

	if err != nil {
		return nil, err
	}
	return plaintext, nil
}


//reading the header

lenBuf := make([]byte, 4)
_, err := io.ReadFull(reader, lenBuf)

//read ciphertext of length

length := binary.BigEndian.Uint32(lenBuf)
ciphertext := make([]byte, length)
_, err = io.ReadFull(reader, ciphertext)

Multiple Concurrent Connections
----------------------------------
Multiple clients connections can be simultanously handled in the program using goroutines. For each incoming client, a goroutine is used, which ensures that the server can service multiple clients without blocking any single connection.

