package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	wgConfigPath = "/etc/wireguard/wg0.conf"
	ipv4Base     = "10.25."
	ipv6Base     = "fd42:42:42::"
)

// Function to execute a command and return its output or error
func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// Function to parse WireGuard configuration
func parseWGConfig() (map[string]string, error) {
	output, err := execCommand("wg", "show", "all", "dump")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	peers := make(map[string]string)

	for _, line := range lines {
		if strings.HasPrefix(line, "peer:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				publicKey := fields[1]
				peers[publicKey] = ""
			}
		}
	}

	return peers, nil
}

// Function to get the next available IP address
func getNextIP(existingIPs map[string]bool, isIPv6 bool) (string, error) {
	ipBase := ipv4Base
	ipPrefix := "0.0.0.0/32"
	if isIPv6 {
		ipBase = ipv6Base
		ipPrefix = "0:0:0:0:0:0:0:0/128"
	}

	for i := 0; i < 255; i++ {
		ip := fmt.Sprintf("%s%d", ipBase, i)
		if !existingIPs[ip] {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no available IP addresses")
}

// Function to generate keys
func generateKeys() (string, string, string, error) {
	privateKey, err := execCommand("wg", "genkey")
	if err != nil {
		return "", "", "", err
	}
	privateKey = strings.TrimSpace(privateKey)

	publicKey, err := execCommand("echo", privateKey, "|", "wg", "pubkey")
	if err != nil {
		return "", "", "", err
	}
	publicKey = strings.TrimSpace(publicKey)

	presharedKey, err := execCommand("wg", "genpsk")
	if err != nil {
		return "", "", "", err
	}
	presharedKey = strings.TrimSpace(presharedKey)

	return privateKey, publicKey, presharedKey, nil
}

// Function to read and parse the wg0.conf file
func readWGConfig() (map[string]string, error) {
	configFile, err := os.ReadFile(wgConfigPath)
	if err != nil {
		return nil, err
	}

	configLines := strings.Split(string(configFile), "\n")
	peers := make(map[string]string)

	for _, line := range configLines {
		if strings.HasPrefix(line, "PublicKey =") {
			key := strings.TrimSpace(strings.Split(line, "=")[1])
			peers[key] = ""
		}
	}

	return peers, nil
}

// Function to write updated WireGuard configuration
func writeWGConfig(newClientPublicKey, newClientIPv4, newClientIPv6, newClientPrivateKey, newClientPresharedKey string) error {
	configFile, err := os.ReadFile(wgConfigPath)
	if err != nil {
		return err
	}

	config := string(configFile)
	config += fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s, %s
PresharedKey = %s
`, newClientPublicKey, newClientIPv4, newClientIPv6, newClientPresharedKey)

	err = os.WriteFile(wgConfigPath, []byte(config), 0644)
	if err != nil {
		return err
	}

	_, err = execCommand("systemctl", "reload", "wg-quick@wg0")
	if err != nil {
		return err
	}

	return nil
}

func handleTransferCommand() error {
	peers, err := parseWGConfig()
	if err != nil {
		return err
	}

	result := make(map[string]interface{})
	for key := range peers {
		result[key] = 0
	}

	jsonResult, err := json.Marshal(result)
	if err != nil {
		return err
	}

	fmt.Println(string(jsonResult))
	return nil
}

func handleNewClientCommand() error {
	peers, err := parseWGConfig()
	if err != nil {
		return err
	}

	existingIPs := make(map[string]bool)
	for ip := range peers {
		existingIPs[ip] = true
	}

	newClientIPv4, err := getNextIP(existingIPs, false)
	if err != nil {
		return err
	}

	newClientIPv6, err := getNextIP(existingIPs, true)
	if err != nil {
		return err
	}

	privateKey, publicKey, presharedKey, err := generateKeys()
	if err != nil {
		return err
	}

	err = writeWGConfig(publicKey, newClientIPv4, newClientIPv6, privateKey, presharedKey)
	if err != nil {
		return err
	}

	result := map[string]string{
		"privatekey":   privateKey,
		"publickey":    publicKey,
		"presharedkey": presharedKey,
		"ipv4":         newClientIPv4,
		"ipv6":         newClientIPv6,
	}

	jsonResult, err := json.Marshal(result)
	if err != nil {
		return err
	}

	fmt.Println(string(jsonResult))
	return nil
}

func handleDeleteCommand(key string) error {
	configLines, err := os.ReadFile(wgConfigPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(configLines), "\n")
	var newConfig []string

	insidePeerSection := false
	for _, line := range lines {
		if strings.HasPrefix(line, "[Peer]") {
			insidePeerSection = true
		} else if strings.HasPrefix(line, "PublicKey =") && insidePeerSection {
			if strings.TrimSpace(strings.Split(line, "=")[1]) == key {
				insidePeerSection = false
				continue
			}
		}
		if !insidePeerSection || !strings.HasPrefix(line, "[Peer]") {
			newConfig = append(newConfig, line)
		}
	}

	err = os.WriteFile(wgConfigPath, []byte(strings.Join(newConfig, "\n")), 0644)
	if err != nil {
		return err
	}

	_, err = execCommand("systemctl", "reload", "wg-quick@wg0")
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <command> [options]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "transfer":
		if err := handleTransferCommand(); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	case "newclient":
		if err := handleNewClientCommand(); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven delete <key>")
			os.Exit(1)
		}
		if err := handleDeleteCommand(os.Args[2]); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}
