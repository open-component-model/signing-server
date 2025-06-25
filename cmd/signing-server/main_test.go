package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestSoftHSMConcurrentSignRequests(t *testing.T) {
	hsmModule := os.Getenv("HSM_MODULE")
	if hsmModule == "" {
		t.Skip("HSM_MODULE environment variable is not set")
	}
	tokenLabel := os.Getenv("TOKEN_LABEL")
	if tokenLabel == "" {
		t.Skip("TOKEN_LABEL environment variable is not set")
	}
	keyLabel := os.Getenv("KEY_LABEL")
	if keyLabel == "" {
		t.Skip("KEY_LABEL environment variable is not set")
	}
	hsmPin := os.Getenv("HSM_PIN")
	if hsmPin == "" {
		t.Skip("HSM_PIN environment variable is not set")
	}

	const (
		base      = "http://localhost:8080"
		healthURL = base + "/healthz"
		url       = base + "/sign/rsassa-pss?hashAlgorithm=sha256"
		bodyHex   = "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"
	)

	var (
		headers = map[string]string{
			"Content-Type":     "text/plain",
			"Content-Encoding": "hex",
			"Accept":           "application/x-pem-file",
		}
	)

	l, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(func() {
		cancel()
	})

	go func() {
		if err := run(&Config{
			HSMModule:        strings.TrimSpace(string(hsmModule)),
			HSMTokenLabel:    tokenLabel,
			HSMSlot:          -1,
			HSMKeyLabel:      keyLabel,
			HSMPass:          hsmPin,
			Port:             "8080",
			DisableHTTPS:     true,
			DisableAuth:      true,
			MaxBodySizeBytes: 2048,
			Logger:           l,
			RunServer:        true,
		}); err != nil {
			cancel()
			t.Fatalf("Failed to start signing server: %v", err)
		}
	}()

	var wg sync.WaitGroup
	client := &http.Client{Timeout: 10 * time.Second}

outer:
	for {
		select {
		case <-ctx.Done():
			t.Fatal("Test context was cancelled before health check passed")
		default:
			log.Println("Waiting for signing server to be ready...")
			healthReq, err := http.NewRequest(http.MethodGet, healthURL, nil)
			if err != nil {
				t.Fatalf("Health request creation failed: %v", err)
			}
			healthResp, _ := client.Do(healthReq)
			if healthResp != nil && healthResp.StatusCode == http.StatusOK {
				log.Println("Health check passed")
				break outer
			}
		}
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)

		go func(index int) {
			defer wg.Done()

			req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(bodyHex))
			if err != nil {
				t.Errorf("Request %d creation failed: %v", index, err)
				return
			}

			for k, v := range headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("Request %d failed: %v", index, err)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Request %d read body failed: %v", index, err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Request %d failed with status %d: %s", index, resp.StatusCode, body)
				return
			}

			block, _ := pem.Decode(body)
			if block == nil || block.Type != "SIGNATURE" {
				log.Fatal("Failed to parse PEM block")
			}

			hsmPublicKeyFile := os.Getenv("HSM_PUBLIC_KEY_FILE")
			if hsmPublicKeyFile == "" {
				log.Println("HSM_PUBLIC_KEY_FILE environment variable is not set, skipping public key verification")
			} else {
				if block == nil || block.Type != "PUBLIC KEY" {
					log.Fatal("Failed to parse PEM block for public key")
				}
				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					log.Fatalf("Failed to parse public key: %v", err)
				}
				rsaPubKey, ok := pub.(*rsa.PublicKey)
				if !ok {
					log.Fatal("Public key is not of type RSA")
				}
				rawDigest, err := hex.DecodeString(bodyHex)
				if err != nil {
					log.Fatalf("Failed to decode hex body: %v", err)
				}
				if err := rsa.VerifyPSS(rsaPubKey, crypto.SHA256, rawDigest, block.Bytes, nil); err != nil {
					log.Fatalf("Signature verification failed: %v", err)
				}
			}

			fmt.Printf("Decoded signature: %x\n", block.Bytes)

			log.Printf("Response %d: %d - %.100q\n", index, resp.StatusCode, body)
		}(i)
	}

	wg.Wait()
}
