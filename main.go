package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/crypto/ed25519"
)

const (
	wgConfPath = "/etc/wireguard/wg0.conf"
	ipRange    = "10.25"
	ipStart    = 2 // Starting IP index in the range
	ipEnd      = 254 // Ending IP index
)

func runCommand(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	return string(out), err
}

func parseWGConf() (map[string]struct{}, error) {
	conf, err := ioutil.ReadFile(wgConfPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(conf), "\n")
	peers := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PublicKey = ") {
			key := strings.TrimPrefix(line, "PublicKey = ")
			peers[key] = struct{}{}
		}
	}
	return peers, nil
}

func parseWGConfIPs() (map[string]struct{}, error) {
	conf, err := ioutil.ReadFile(wgConfPath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(conf), "\n")
	usedIPs := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AllowedIPs = ") {
			ipRange := strings.TrimPrefix(line, "AllowedIPs = ")
			ipAddresses := strings.Split(ipRange, ",")
			for _, ip := range ipAddresses {
				ip = strings.TrimSpace(ip)
				if net.ParseIP(ip) != nil {
					usedIPs[ip] = struct{}{}
				}
			}
		}
	}
	return usedIPs, nil
}

func getAvailableIP(usedIPs map[string]struct{}) (string, error) {
	for i := ipStart; i <= ipEnd; i++ {
		ip := fmt.Sprintf("%s.%d", ipRange, i)
		if _, ok := usedIPs[ip]; !ok {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no available IP addresses in the range")
}

func collectUsers() (map[string]interface{}, error) {
	peers, err := parseWGConf()
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})
	for key := range peers {
		data[key] = 0 // Placeholder for actual transfer amount
	}

	return data, nil
}

func newClient() (map[string]string, error) {
	// Generate keys
	privKey, pubKey, err := generateKeys()
	if err != nil {
		return nil, err
	}

	// Get available IP
	usedIPs, err := parseWGConfIPs()
	if err != nil {
		return nil, err
	}
	ip, err := getAvailableIP(usedIPs)
	if err != nil {
		return nil, err
	}

	// Append new client to wg0.conf
	newClientConfig := fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
`, pubKey, privKey, ip)

	conf, err := ioutil.ReadFile(wgConfPath)
	if err != nil {
		return nil, err
	}

	conf = append(conf, []byte(newClientConfig)...)
	err = ioutil.WriteFile(wgConfPath, conf, 0644)
	if err != nil {
		return nil, err
	}

	// Reload WireGuard
	_, err = runCommand("systemctl", "reload", "wg-quick@wg0")
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"privatekey": privKey,
		"publickey":  pubKey,
		"ip":         ip,
	}, nil
}

func deleteClient(key string) error {
	conf, err := ioutil.ReadFile(wgConfPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(conf), "\n")
	var newLines []string
	insidePeer := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[Peer]") {
			insidePeer = true
		}
		if insidePeer {
			if strings.HasPrefix(line, "PublicKey = ") {
				if strings.TrimPrefix(line, "PublicKey = ") == key {
					insidePeer = false
					continue
				}
			}
		}
		if !insidePeer {
			newLines = append(newLines, line)
		}
	}

	conf = []byte(strings.Join(newLines, "\n"))
	err = ioutil.WriteFile(wgConfPath, conf, 0644)
	if err != nil {
		return err
	}

	// Reload WireGuard
	_, err = runCommand("systemctl", "reload", "wg-quick@wg0")
	if err != nil {
		return err
	}

	return nil
}

func generateKeys() (string, string, error) {
	// Generate a new key pair
	_, priv := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	return fmt.Sprintf("%x", priv), fmt.Sprintf("%x", pub), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <command> [arguments]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "transfer":
		users, err := collectUsers()
		if err != nil {
			fmt.Println("Error collecting users:", err)
			os.Exit(1)
		}
		data, err := json.Marshal(users)
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	case "newclient":
		keys, err := newClient()
		if err != nil {
			fmt.Println("Error creating new client:", err)
			os.Exit(1)
		}
		data, err := json.Marshal(keys)
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven delete <key>")
			os.Exit(1)
		}
		key := os.Args[2]
		err := deleteClient(key)
		if err != nil {
			fmt.Println("Error deleting client:", err)
			os.Exit(1)
		}
		fmt.Println("Client deleted successfully.")
	default:
		fmt.Println("Unknown command:", cmd)
		os.Exit(1)
	}
}
