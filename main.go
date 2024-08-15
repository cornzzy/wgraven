// wgraven.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <command> [options]")
		return
	}

	command := os.Args[1]
	switch command {
	case "transfer":
		handleTransfer()
	case "newclient":
		handleNewClient()
	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("Usage: wgraven delete <key>")
			return
		}
		handleDelete(os.Args[2])
	default:
		fmt.Println("Unknown command:", command)
	}
}

func runCommand(cmd string, args ...string) (string, error) {
	output, err := exec.Command(cmd, args...).CombinedOutput()
	return string(output), err
}

func handleTransfer() {
	output, err := runCommand("wg", "show", "wg0", "transfer")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	transferMap := make(map[string]map[string]int64)

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		key := parts[0]
		upload, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			fmt.Println("Error parsing upload value:", err)
			return
		}
		download, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			fmt.Println("Error parsing download value:", err)
			return
		}
		transferMap[key] = map[string]int64{
			"upload":   upload,
			"download": download,
		}
	}

	jsonData, err := json.Marshal(transferMap)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}
	fmt.Println(string(jsonData))
}

func handleNewClient() {
	wgConf, err := runCommand("cat", "/etc/wireguard/wg0.conf")
	if err != nil {
		fmt.Println("Error reading wg0.conf:", err)
		return
	}

	ipPrefix := "10.25."
	ipv6Prefix := "fd00:10:25::"

	ipUsed := make(map[string]bool)
	ipv6Used := make(map[string]bool)

	lines := strings.Split(wgConf, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Address = ") {
			address := strings.TrimPrefix(line, "Address = ")
			ipUsed[address] = true
		}
		if strings.HasPrefix(line, "Address6 = ") {
			address := strings.TrimPrefix(line, "Address6 = ")
			ipv6Used[address] = true
		}
	}

	var newIP, newIPv6 string
	for i := 2; i <= 254; i++ {
		newIP = fmt.Sprintf("%s%d", ipPrefix, i)
		if !ipUsed[newIP] {
			break
		}
	}
	for i := 1; i <= 65534; i++ {
		newIPv6 = fmt.Sprintf("%s%x", ipv6Prefix, i)
		if !ipv6Used[newIPv6] {
			break
		}
	}

	// Generate keys
	privateKey, err := runCommand("wg", "genkey")
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
	publicKey, err := runCommand("wg", "pubkey")
	if err != nil {
		fmt.Println("Error generating public key:", err)
		return
	}
	presharedKey, err := runCommand("wg", "genpsk")
	if err != nil {
		fmt.Println("Error generating preshared key:", err)
		return
	}

	clientPrivateKey := strings.TrimSpace(privateKey)
	clientPublicKey := strings.TrimSpace(publicKey)
	clientPresharedKey := strings.TrimSpace(presharedKey)

	// Update wg0.conf
	conf := fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s, %s
`, clientPublicKey, clientPresharedKey, newIP+"/32", newIPv6+"/128")

	confFile, err := os.OpenFile("/etc/wireguard/wg0.conf", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Println("Error opening wg0.conf:", err)
		return
	}
	defer confFile.Close()

	if _, err := confFile.WriteString(conf); err != nil {
		fmt.Println("Error writing to wg0.conf:", err)
		return
	}

	_, err = runCommand("systemctl", "reload", "wg-quick@wg0")
	if err != nil {
		fmt.Println("Error reloading wg-quick:", err)
		return
	}

	// Return JSON
	clientData := map[string]string{
		"privatekey":   clientPrivateKey,
		"publickey":    clientPublicKey,
		"presharedkey": clientPresharedKey,
		"ip":           newIP,
		"ipv6":         newIPv6,
	}
	jsonData, err := json.Marshal(clientData)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}
	fmt.Println(string(jsonData))
}

func handleDelete(key string) {
	wgConf, err := runCommand("cat", "/etc/wireguard/wg0.conf")
	if err != nil {
		fmt.Println("Error reading wg0.conf:", err)
		return
	}

	lines := strings.Split(wgConf, "\n")
	var updatedLines []string
	inPeerSection := false
	for _, line := range lines {
		if strings.HasPrefix(line, "[Peer]") {
			inPeerSection = true
		}
		if inPeerSection && strings.HasPrefix(line, "PublicKey = ") {
			if strings.TrimSpace(strings.TrimPrefix(line, "PublicKey = ")) == key {
				inPeerSection = false
				continue
			}
		}
		if inPeerSection && line == "" {
			inPeerSection = false
		}
		updatedLines = append(updatedLines, line)
	}

	if !inPeerSection {
		fmt.Println("Error: Peer with given key not found.")
		return
	}

	err = os.WriteFile("/etc/wireguard/wg0.conf", []byte(strings.Join(updatedLines, "\n")), 0600)
	if err != nil {
		fmt.Println("Error writing to wg0.conf:", err)
		return
	}

	_, err = runCommand("systemctl", "reload", "wg-quick@wg0")
	if err != nil {
		fmt.Println("Error reloading wg-quick:", err)
		return
	}

	fmt.Println("Peer removed and service reloaded.")
}
