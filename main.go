package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const wgConfPath = "/etc/wireguard/wg0.conf"

type Peer struct {
	PrivateKey   string `json:"privateKey"`
	Address      string `json:"address"`
	PresharedKey string `json:"presharedKey"`
	PublicKey    string `json:"publicKey"`
}

func addPeer(ip string) (Peer, error) {
	// Generate keys
	privateKey, err := generateKey("wg genkey")
	if err != nil {
		return Peer{}, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey, err := generateKey(fmt.Sprintf("echo %s | wg pubkey", privateKey))
	if err != nil {
		return Peer{}, fmt.Errorf("failed to generate public key: %v", err)
	}

	// Generate a pre-shared key
	presharedKey, err := generateKey("wg genpsk")
	if err != nil {
		return Peer{}, fmt.Errorf("failed to generate pre-shared key: %v", err)
	}

	peer := Peer{
		PrivateKey:   privateKey,
		Address:      ip,
		PresharedKey: presharedKey,
		PublicKey:    publicKey,
	}

	// Append peer config to wg0.conf
	err = appendPeerToConf(peer)
	if err != nil {
		return Peer{}, err
	}

	// Apply the configuration using wg-quick
	err = applyWGConfig()
	if err != nil {
		return Peer{}, err
	}

	return peer, nil
}

func deletePeer(publicKey string) error {
	// Read the config and find the peer by its public key
	file, err := os.Open(wgConfPath)
	if err != nil {
		return fmt.Errorf("could not open wg0.conf: %v", err)
	}
	defer file.Close()

	var newConf []string
	scanner := bufio.NewScanner(file)
	var skipPeer bool
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PublicKey = "+publicKey) {
			// Skip lines related to the peer
			skipPeer = true
		} else if strings.TrimSpace(line) == "" && skipPeer {
			// End of peer section
			skipPeer = false
		} else if !skipPeer {
			newConf = append(newConf, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading wg0.conf: %v", err)
	}

	// Write back the new config without the peer
	err = os.WriteFile(wgConfPath, []byte(strings.Join(newConf, "\n")), 0600)
	if err != nil {
		return fmt.Errorf("could not write to wg0.conf: %v", err)
	}

	// Apply the configuration using wg-quick
	return applyWGConfig()
}

func generateKey(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func appendPeerToConf(peer Peer) error {
	peerConfig := fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s
PresharedKey = %s
`, peer.PublicKey, peer.Address, peer.PresharedKey)

	f, err := os.OpenFile(wgConfPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("could not open wg0.conf for writing: %v", err)
	}
	defer f.Close()

	if _, err = f.WriteString(peerConfig); err != nil {
		return fmt.Errorf("failed to write peer config: %v", err)
	}
	return nil
}

func applyWGConfig() error {
	// Apply changes with wg syncconf
	cmd := exec.Command("bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0)")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to apply WireGuard config: %v", err)
	}
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: wgraven [add <ip> | delete <publicKey>]")
		return
	}

	command := os.Args[1]
	switch command {
	case "add":
		ip := os.Args[2]
		peer, err := addPeer(ip)
		if err != nil {
			log.Fatalf("Error adding peer: %v", err)
		}

		peerJSON, _ := json.Marshal(peer)
		fmt.Println(string(peerJSON))

	case "delete":
		publicKey := os.Args[2]
		err := deletePeer(publicKey)
		if err != nil {
			log.Fatalf("Error deleting peer: %v", err)
		}

		fmt.Println(`{"status":"peer deleted successfully"}`)
	default:
		fmt.Println("Unknown command")
	}
}
