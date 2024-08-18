package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	ipv4Subnet  = "10.25.0.0/16"
	ipv6Subnet  = "fd42:42:42::0/112"
	ipv4Prefix  = 32
	ipv6Prefix  = 128
	ipv4Range   = 65534
	ipv6Range   = 65514
)

func runCommand(cmd string, args ...string) (string, error) {
	var out bytes.Buffer
	var stderr bytes.Buffer
	command := exec.Command(cmd, args...)
	command.Stdout = &out
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		return "", fmt.Errorf("command error: %s", stderr.String())
	}
	return out.String(), nil
}

func getAvailableIP(currentIPs []string, subnet string, prefix int) (string, error) {
	allocatedIPs := make(map[string]bool)
	for _, ip := range currentIPs {
		allocatedIPs[ip] = true
	}

	// Extract the base IP and the CIDR range
	parts := strings.Split(subnet, "/")
	baseIP := parts[0]
	rangeSize, _ := strconv.Atoi(parts[1])
	baseIPInt := ipToInt(baseIP)
	maxIPInt := baseIPInt + (1 << (32 - rangeSize)) - 1

	// Find the next available IP
	for i := 1; i <= ipv4Range; i++ {
		ip := intToIP(baseIPInt + i)
		if !allocatedIPs[ip] {
			return ip + "/" + strconv.Itoa(prefix), nil
		}
	}

	return "", errors.New("no available IPs found")
}

func ipToInt(ip string) int {
	parts := strings.Split(ip, ".")
	a, _ := strconv.Atoi(parts[0])
	b, _ := strconv.Atoi(parts[1])
	c, _ := strconv.Atoi(parts[2])
	d, _ := strconv.Atoi(parts[3])
	return (a << 24) + (b << 16) + (c << 8) + d
}

func intToIP(ipInt int) string {
	a := (ipInt >> 24) & 0xFF
	b := (ipInt >> 16) & 0xFF
	c := (ipInt >> 8) & 0xFF
	d := ipInt & 0xFF
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func generateKey() (string, error) {
	key, err := runCommand("wg", "genkey")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(key), nil
}

func generatePresharedKey() (string, error) {
	key, err := runCommand("wg", "genpsk")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(key), nil
}

func getPublicKey(privateKey string) (string, error) {
	publicKey, err := runCommand("wg", "pubkey")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(publicKey), nil
}

func getPeers() (map[string][]string, error) {
	output, err := runCommand("wg", "show", "wg0", "allowed-ips")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	peers := make(map[string][]string)
	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		pubKey := parts[0]
		allowedIPs := parts[1:]
		peers[pubKey] = allowedIPs
	}

	return peers, nil
}

func addPeer() error {
	peers, err := getPeers()
	if err != nil {
		return err
	}

	ipv4Available, err := getAvailableIP(getAllIPv4(peers), ipv4Subnet, ipv4Prefix)
	if err != nil {
		return err
	}

	ipv6Available, err := getAvailableIP(getAllIPv6(peers), ipv6Subnet, ipv6Prefix)
	if err != nil {
		return err
	}

	privateKey, err := generateKey()
	if err != nil {
		return err
	}

	presharedKey, err := generatePresharedKey()
	if err != nil {
		return err
	}

	publicKey, err := getPublicKey(privateKey)
	if err != nil {
		return err
	}

	config := map[string]string{
		"privatekey":   privateKey,
		"address":      ipv4Available + ", " + ipv6Available,
		"presharedkey": presharedKey,
		"publickey":    publicKey,
	}

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))
	return nil
}

func getAllIPv4(peers map[string][]string) []string {
	var ips []string
	for _, allowedIPs := range peers {
		for _, ip := range allowedIPs {
			if strings.Contains(ip, ".") {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func getAllIPv6(peers map[string][]string) []string {
	var ips []string
	for _, allowedIPs := range peers {
		for _, ip := range allowedIPs {
			if strings.Contains(ip, ":") {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func deletePeer(publicKey string) error {
	_, err := runCommand("wg", "set", "wg0", "peer", publicKey, "remove")
	return err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  add      Adds a new client (peer).")
		fmt.Println("  delete   Deletes a client (peer) by public key.")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "add":
		if err := addPeer(); err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven delete <publickey>")
			os.Exit(1)
		}
		publicKey := os.Args[2]
		if err := deletePeer(publicKey); err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Usage: wgraven <command> [options]")
		os.Exit(1)
	}
}
