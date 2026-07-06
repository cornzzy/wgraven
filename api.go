package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiServer struct {
	apiKey string
	quiet  bool
}

func generateAPIKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "wgraven",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func (s *apiServer) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !s.quiet {
		log.Printf("Error writing JSON response: %v", err)
	}
}

func (s *apiServer) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

func (s *apiServer) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != s.apiKey {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch parts[1] {
	case "add":
		if len(parts) != 3 {
			http.NotFound(w, r)
			return
		}
		ip, err := url.PathUnescape(parts[2])
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid ip")
			return
		}
		peer, err := addPeer(ip)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, peer)

	case "delete":
		if len(parts) != 3 {
			http.NotFound(w, r)
			return
		}
		clientPublicKey, err := url.PathUnescape(parts[2])
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid client public key")
			return
		}
		if err := deletePeer(clientPublicKey); err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})

	case "transfer":
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		transferInfo, err := transfer()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, transferInfo)

	default:
		http.NotFound(w, r)
	}
}

func runAPI(port int, quiet bool) error {
	if quiet {
		log.SetOutput(io.Discard)
	}

	apiKey, err := generateAPIKey()
	if err != nil {
		return fmt.Errorf("generating API key: %w", err)
	}

	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generating TLS certificate: %w", err)
	}

	server := &apiServer{apiKey: apiKey, quiet: quiet}
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handle)

	addr := fmt.Sprintf(":%d", port)
	httpsServer := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	fmt.Printf("API key: %s\n", apiKey)
	if !quiet {
		fmt.Printf("Listening on https://0.0.0.0:%d/%s/\n", port, apiKey)
		fmt.Printf("  Add peer:    https://<ip>:%d/%s/add/<ip>\n", port, apiKey)
		fmt.Printf("  Delete peer: https://<ip>:%d/%s/delete/<clientpubkey>\n", port, apiKey)
		fmt.Printf("  Transfer:    https://<ip>:%d/%s/transfer\n", port, apiKey)
		log.Printf("Starting HTTPS API on %s", addr)
	}

	return httpsServer.ListenAndServeTLS("", "")
}
