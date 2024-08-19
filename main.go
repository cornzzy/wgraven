package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type output struct {
	PrivateKey   string `json:"privateKey"`
	Address      string `json:"address"`
	PresharedKey string `json:"presharedKey"`
}

func main() {
	ip := flag.String("ip", "", "IP address for the new peer")
	flag.Parse()

	if *ip == "" {
		log.Fatalf("IP address must be specified using --ip")
	}

	// Generate a new private key
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := privateKey.PublicKey()

	// Generate a new preshared key
	presharedKey, err := wgtypes.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate preshared key: %v", err)
	}

	// Add the peer using the wg command-line tool
	cmd := exec.Command("wg", "set", "wg0", "peer", publicKey.String(), "allowed-ips", *ip)
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to add peer: %v", err)
	}

	// Append the new peer to the wg0.conf file
	wg0conf := "/etc/wireguard/wg0.conf"
	confEntry := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", publicKey.String(), presharedKey.String(), *ip)
	if err := appendToFile(wg0conf, confEntry); err != nil {
		log.Fatalf("Failed to append to wg0.conf: %v", err)
	}

	// Output JSON data
	out := output{
		PrivateKey:   privateKey.String(),
		Address:      *ip,
		PresharedKey: presharedKey.String(),
	}

	jsonOutput, err := json.Marshal(out)
	if err != nil {
		log.Fatalf("Failed to generate JSON output: %v", err)
	}

	fmt.Println(string(jsonOutput))
}

func appendToFile(filename, text string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return err
	}
	return nil
}
