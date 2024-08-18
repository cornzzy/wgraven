package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/yl2chen/cidranger"
)

const (
	ipv4Subnet    = "10.25.0.0/16"
	ipv6Subnet    = "fd42:42:42::0/112"
	ipv4RangeSize = 256
	ipv6RangeSize = 256
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <command> [options]")
		return
	}

	command := os.Args[1]
	switch command {
	case "add":
		err := addPeer()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven delete <publickey>")
			return
		}
		publicKey := os.Args[2]
		err := deletePeer(publicKey)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	default:
		fmt.Println("Unknown command. Use 'add' or 'delete'")
	}
}

func addPeer() error {
	wgShowOutput, err := exec.Command("wg", "show", "wg0", "allowed-ips").Output()
	if err != nil {
		return err
	}

	ipv4Ranger, ipv6Ranger, err := getAvailableRanges(wgShowOutput)
	if err != nil {
		return err
	}

	ipv4Addr, ipv6Addr, err := getNextAvailableIPs(ipv4Ranger, ipv6Ranger)
	if err != nil {
		return err
	}

	privateKey, err := generateKey()
	if err != nil {
		return err
	}

	publicKey, err := generatePublicKey(privateKey)
	if err != nil {
		return err
	}

	presharedKey, err := generateKey()
	if err != nil {
		return err
	}

	// Output in JSON format
	output := map[string]string{
		"privatekey":  privateKey,
		"address":     fmt.Sprintf("%s/32, %s/128", ipv4Addr, ipv6Addr),
		"presharedkey": presharedKey,
		"publickey":   publicKey,
	}

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonOutput))
	return nil
}

func deletePeer(publicKey string) error {
	_, err := exec.Command("wg", "set", "wg0", "peer", publicKey, "remove").Output()
	if err != nil {
		return err
	}
	fmt.Println("Peer removed successfully")
	return nil
}

func getAvailableRanges(wgOutput []byte) (cidranger.Ranger, cidranger.Ranger, error) {
	ipv4Ranger, _ := cidranger.NewRanger()
	ipv6Ranger, _ := cidranger.NewRanger()

	scanner := bufio.NewScanner(bytes.NewReader(wgOutput))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		ipRanges := fields[1:]
		for _, ipRange := range ipRanges {
			if strings.Contains(ipRange, ":") {
				ipv6Ranger.Add(cidranger.NewCIDRRange(ipRange))
			} else {
				ipv4Ranger.Add(cidranger.NewCIDRRange(ipRange))
			}
		}
	}
	return ipv4Ranger, ipv6Ranger, scanner.Err()
}

func getNextAvailableIPs(ipv4Ranger, ipv6Ranger cidranger.Ranger) (string, string, error) {
	ipv4Range, err := cidranger.NewCIDRRange(ipv4Subnet)
	if err != nil {
		return "", "", err
	}
	ipv6Range, err := cidranger.NewCIDRRange(ipv6Subnet)
	if err != nil {
		return "", "", err
	}

	ipv4Addr, _ := ipv4Range.NextAvailable(ipv4Ranger)
	ipv6Addr, _ := ipv6Range.NextAvailable(ipv6Ranger)

	return ipv4Addr, ipv6Addr, nil
}

func generateKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func generatePublicKey(privateKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	publicKey, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(publicKey)), nil
}
