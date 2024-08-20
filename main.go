package main

import (
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

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: wgraven <add|delete> <arguments>")
		os.Exit(1)
	}

	command := os.Args[1]
	arg := os.Args[2]

	switch command {
	case "add":
		addPeer(arg)
	case "delete":
		deletePeer(arg)
	default:
		fmt.Println("Unknown command:", command)
		os.Exit(1)
	}
}
