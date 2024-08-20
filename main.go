package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	
)

type Peer struct {
	ClientPrivateKey string `json:"clientPrivateKey"`
	Address          string `json:"address"`
	PresharedKey     string `json:"presharedKey"`
	ClientPublicKey  string `json:"clientPublicKey"`
}

type TransferInfo struct {
	Download string `json:"download"`
	Upload   string `json:"upload"`
}

func addPeer(ip string) {
	// Generate key pair
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}
	clientPublicKey := clientPrivateKey.PublicKey()

	// Generate preshared key
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating preshared key: %v", err)
	}

	// Create the peer
	cmd := exec.Command("wg", "set", "wg0", "peer", clientPublicKey.String(), "allowed-ips", ip, "preshared-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(psk.String())
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error adding peer: %v", err)
	}

	// Save the configuration
	cmd = exec.Command("wg-quick", "save", "wg0")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error saving configuration: %v", err)
	}

	// Create the response
	peer := Peer{
		ClientPrivateKey: clientPrivateKey.String(),
		Address:          ip,
		PresharedKey:     psk.String(),
		ClientPublicKey:  clientPublicKey.String(),
	}

	// Output JSON
	output, err := json.Marshal(peer)
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}

	fmt.Println(string(output))
}

func deletePeer(clientPublicKey string) {
	// Remove the peer
	cmd := exec.Command("wg", "set", "wg0", "peer", clientPublicKey, "remove")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error removing peer: %v", err)
	}

	// Save the configuration
	cmd = exec.Command("wg-quick", "save", "wg0")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error saving configuration: %v", err)
	}

	fmt.Println("{\"status\": \"success\"}")
}

func transfer() {
	// Get transfer information
	cmd := exec.Command("wg", "show", "wg0", "transfer")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error getting transfer information: %v", err)
	}

	lines := strings.Split(out.String(), "\n")
	transferInfo := make(map[string]TransferInfo)

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		publicKey := parts[0]
		download := parts[1]
		upload := parts[2]

		transferInfo[publicKey] = TransferInfo{
			Download: download,
			Upload:   upload,
		}
	}

	// Output JSON
	output, err := json.Marshal(transferInfo)
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}

	fmt.Println(string(output))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <add|delete|transfer> <arguments>")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "add":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven add <ip>")
			os.Exit(1)
		}
		addPeer(os.Args[2])
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven delete <clientpublickey>")
			os.Exit(1)
		}
		deletePeer(os.Args[2])
	case "transfer":
		transfer()
	default:
		fmt.Println("Unknown command:", command)
		os.Exit(1)
	}
}
