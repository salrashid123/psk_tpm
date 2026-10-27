package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	//"net/http/httputil"

	"github.com/golang-jwt/jwt/v5"
	dtls "github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
)

var (
	keydb = make(map[string]string)
)

const ()

func main() {

	// populate the hmac key lookup table
	keydb["client1"] = "6d795f6170695f6b6579"

	//fmt.Printf("%s\n", PSK_KEY)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}

	w, err := os.OpenFile("dtls_keylog.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}

	l, err := dtls.ListenAddr("udp", addr,
		dtls.WithPSK(nil, func(identities [][]byte) (*dtls.PSK, error) {
			fmt.Printf("Full Client's identity: %s \n", identities[0])

			if len(identities) == 0 {
				return nil, errors.New("No PSK Identity provided")
			}
			claims := &jwt.RegisteredClaims{}

			err := json.Unmarshal([]byte(identities[0]), &claims)
			if err != nil {
				return nil, err
			}

			fmt.Printf("ClientID: %s\n", claims.Issuer)
			fmt.Printf("Nonce: %s\n", claims.ID)

			/// this is where you'd use isser to lookup lookup the hmac key to use

			value, ok := keydb[claims.Issuer]
			if !ok {
				return nil, errors.New("Key not found in db")
			}
			k, err := hex.DecodeString(value)
			if err != nil {
				return nil, err
			}

			mac := hmac.New(sha256.New, k)
			mac.Write(identities[0])

			result := mac.Sum(nil)

			return &dtls.PSK{Identity: identities[0], Key: result}, nil
		}),
		dtls.WithKeyLogWriter(w),
		dtls.WithCipherSuites(ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	)
	if err != nil {
		panic(err)
	}
	defer l.Close()

	fmt.Println("Starting dtls server")
	for {

		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			io.Copy(c, c)
			c.Close()
		}(conn)
	}

}

func printJSON(data interface{}) {
	prettyJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}
	fmt.Println(string(prettyJSON))
}
