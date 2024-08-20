package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Peer represents the WireGuard peer details
type Peer struct {
	ClientPrivateKey string `json:"clientPrivateKey"`
	Address          string `json:"address"`
	PresharedKey     string `json:"presharedKey"`
	ClientPublicKey  string `json:"clientPublicKey"`
}

// AddPeer adds a new WireGuard peer
func AddPeer(ip string) {
	privateKey := executeCommand("wg", "genkey")
	publicKey := executeCommandWithInput("wg", privateKey, "pubkey")
	presharedKey := executeCommand("wg", "genpsk")

	peer := Peer{
		ClientPrivateKey: strings.TrimSpace(privateKey),
		Address:          ip,
		PresharedKey:     strings.TrimSpace(presharedKey),
		ClientPublicKey:  strings.TrimSpace(publicKey),
	}

	// Adding the peer to the wg0 interface
	executeCommand("wg", "set", "wg0", "peer", peer.ClientPublicKey, "allowed-ips", ip, "preshared-key", peer.PresharedKey)

	// Saving the wg0 configuration
	executeCommand("wg-quick", "save", "wg0")

	// Output the peer details in JSON format
	jsonOutput, err := json.Marshal(peer)
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}

	fmt.Println(string(jsonOutput))
}

// DeletePeer deletes a WireGuard peer by its public key
func DeletePeer(clientPublicKey string) {
	// Removing the peer from the wg0 interface
	executeCommand("wg", "set", "wg0", "peer", clientPublicKey, "remove")

	// Saving the wg0 configuration
	executeCommand("wg-quick", "save", "wg0")

	// Output success message in JSON format
	response := map[string]string{
		"status": "success",
		"message": fmt.Sprintf("Peer with public key %s removed", clientPublicKey),
	}

	jsonOutput, err := json.Marshal(response)
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}

	fmt.Println(string(jsonOutput))
}

// executeCommand runs a command and returns its output
func executeCommand(name string, arg ...string) string {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
	return out.String()
}

// executeCommandWithInput runs a command with input and returns its output
func executeCommandWithInput(name string, input string, arg ...string) string {
	cmd := exec.Command(name, arg...)
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
	return out.String()
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <add|delete> <args>", os.Args[0])
	}

	command := os.Args[1]
	switch command {
	case "add":
		if len(os.Args) != 3 {
			log.Fatalf("Usage: %s add <ip>", os.Args[0])
		}
		ip := os.Args[2]
		AddPeer(ip)
	case "delete":
		if len(os.Args) != 3 {
			log.Fatalf("Usage: %s delete <clientpublickey>", os.Args[0])
		}
		clientPublicKey := os.Args[2]
		DeletePeer(clientPublicKey)
	default:
		log.Fatalf("Unknown command: %s", command)
	}
}
