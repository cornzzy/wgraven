package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// Peer represents a WireGuard peer.
type Peer struct {
	PrivateKey   string `json:"privateKey"`
	Address      string `json:"address"`
	PresharedKey string `json:"presharedKey"`
	PublicKey    string `json:"publicKey"`
}

func addPeer(ip string) {
	// Generate keys for the new peer
	privateKey := execCommand("wg", "genkey")
	publicKey := execCommand("wg", "pubkey", fmt.Sprintf("<(echo %s)", privateKey))
	presharedKey := execCommand("wg", "genpsk")

	// Format the peer section for wg0.conf
	peerConfig := fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
`, publicKey, presharedKey, ip)

	// Append the new peer to wg0.conf
	appendToFile("/etc/wireguard/wg0.conf", peerConfig)

	// Sync the WireGuard configuration
	execCommand("wg", "syncconf", "wg0", "<(wg-quick strip wg0)")

	// Return the peer data as JSON
	peer := Peer{
		PrivateKey:   privateKey,
		Address:      ip,
		PresharedKey: presharedKey,
		PublicKey:    publicKey,
	}
	peerJSON, _ := json.Marshal(peer)
	fmt.Println(string(peerJSON))
}

func deletePeer(publicKey string) {
	// Read wg0.conf
	data, err := ioutil.ReadFile("/etc/wireguard/wg0.conf")
	if err != nil {
		fmt.Printf(`{"error": "Unable to read wg0.conf: %s"}`, err)
		return
	}

	// Remove the peer with the specified public key
	config := string(data)
	peerStart := strings.Index(config, "[Peer]")
	for peerStart != -1 {
		peerEnd := strings.Index(config[peerStart:], "[Peer]")
		if peerEnd == -1 {
			peerEnd = len(config)
		} else {
			peerEnd += peerStart
		}

		peerConfig := config[peerStart:peerEnd]
		if strings.Contains(peerConfig, fmt.Sprintf("PublicKey = %s", publicKey)) {
			config = config[:peerStart] + config[peerEnd:]
			break
		}
		peerStart = strings.Index(config[peerEnd:], "[Peer]") + peerEnd
	}

	// Write the updated configuration back to wg0.conf
	if err := ioutil.WriteFile("/etc/wireguard/wg0.conf", []byte(config), 0644); err != nil {
		fmt.Printf(`{"error": "Unable to write to wg0.conf: %s"}`, err)
		return
	}

	// Sync the WireGuard configuration
	execCommand("wg", "syncconf", "wg0", "<(wg-quick strip wg0)")

	fmt.Println(`{"status": "success"}`)
}

func execCommand(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf(`{"error": "Command failed: %s"}`, err)
		os.Exit(1)
	}
	return strings.TrimSpace(out.String())
}

func appendToFile(filename string, content string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf(`{"error": "Unable to open file: %s"}`, err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		fmt.Printf(`{"error": "Unable to write to file: %s"}`, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println(`{"error": "Invalid arguments"}`)
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
		fmt.Println(`{"error": "Unknown command"}`)
		os.Exit(1)
	}
}
