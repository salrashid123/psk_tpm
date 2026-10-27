package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"time"
	"uuid"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	dtls "github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	clientIdentity = "client1"
)

var (
	tpmPath        = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	privateKeyFile = flag.String("privateKeyFile", "/tmp/tpm-key.pem", "TPM private key file")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

type TPM struct {
	transport io.ReadWriteCloser
}

func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

func getTPM(s io.ReadWriteCloser) (transport.TPMCloser, error) {
	return &TPM{

		transport: s,
	}, nil
}

func (t *TPM) Close() error {
	return t.transport.Close()
}

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
	flag.Parse()

	//	PSK_KEY := "6d795f6170695f6b6579"

	log.Printf("======= reading key from file ========")
	c, err := os.ReadFile(*privateKeyFile)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return 1
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(key.Parent),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't create primary TPM %q: %v", *tpmPath, err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		fmt.Printf("can't load hmac key: %v", err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Dial("udp", addr,
		dtls.WithPSK(func() ([]dtls.PSK, error) {
			// k, err := hex.DecodeString(PSK_KEY)
			// if err != nil {
			// 	return nil, err
			// }

			jti := uuid.New().String()

			claims := &jwt.RegisteredClaims{
				IssuedAt:  &jwt.NumericDate{time.Now()},
				ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Second * 5)},
				Issuer:    clientIdentity,
				ID:        jti,
			}

			jsonData, err := json.Marshal(claims)
			if err != nil {
				log.Fatalf("Error encoding JSON: %s", err)
			}

			tokenString := string(jsonData)

			fmt.Printf("TOKEN: %s\n", tokenString)

			objAuth := &tpm2.TPM2BAuth{
				Buffer: nil,
			}
			hmacBytes, err := hmac(rwr, []byte(tokenString), hmacKey.ObjectHandle, hmacKey.Name, *objAuth)
			if err != nil {
				return nil, err
			}
			log.Printf("PSK: %s\n", hex.EncodeToString(hmacBytes))

			return []dtls.PSK{{Identity: []byte(tokenString), Key: hmacBytes}}, nil
		}, nil),
		dtls.WithCipherSuites(ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	)
	if err != nil {
		fmt.Printf("Error connecting: %v\n", err)
		return 1
	}

	defer dtlsConn.Close()

	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		fmt.Printf("Failed to handshake with server: %v\n", err)
		return 1
	}
	_, err = dtlsConn.Write([]byte("This is a UDP message"))
	if err != nil {
		fmt.Printf("Write data failed: %v\n", err.Error())
		return 1
	}

	received := make([]byte, 1024)
	_, err = dtlsConn.Read(received)
	if err != nil {
		fmt.Printf("Read data failed: %v\n", err.Error())
		return 1
	}

	fmt.Println(string(received))

	return 0
}

const (
	maxInputBuffer = 1024
)

var ()

func hmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, objAuth tpm2.TPM2BAuth) ([]byte, error) {

	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sasCloser()
	}()

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: sas.Handle(),
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objHandle,
			Name:   objName,
			Auth:   sas,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objName,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}

func decodeHex(h string) []byte {
	data, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return data
}
