package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/net/ipv6"
)

const (
	wgConfPath   = "/etc/wireguard/wg0.conf"
	paramsPath   = "/etc/wireguard/params"
	wgBinary     = "/usr/bin/wg"
	ipv4Subnet   = "10.25.0.0/16"
	ipv6Subnet   = "fd42:42:42::1/112"
	addressBlock = "/32"
	addressBlock6 = "/128"
)

type PeerConfig struct {
	PrivateKey   string `json:"privatekey"`
	Address      string `json:"address"`
	PresharedKey string `json:"presharedkey"`
	PublicKey    string `json:"publickey"`
}

func loadParams() (map[string]string, error) {
	params := make(map[string]string)
	file, err := os.Open(paramsPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var key, value string
	for {
		_, err := fmt.Fscanf(file, "%s=%s\n", &key, &value)
		if err != nil {
			break
		}
		params[key] = value
	}
	return params, nil
}

func execCommand(command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func getCurrentPeers() ([]string, error) {
	out, err := execCommand(wgBinary, "show", "wg0", "allowed-ips")
	if err != nil {
		return nil, err
	}

	peers := strings.Split(string(out), "\n")
	allocatedIPs := make([]string, 0, len(peers))

	for _, peer := range peers {
		if peer != "" {
			parts := strings.Fields(peer)
			if len(parts) > 1 {
				allocatedIPs = append(allocatedIPs, parts[1])
			}
		}
	}
	return allocatedIPs, nil
}

func findNextIP(allocatedIPs []string, subnet string) (string, error) {
	_, ipv4Net, _ := net.ParseCIDR(subnet)
	ip := ipv4Net.IP
	for {
		ip = ipv4Net.IP.To4()
		ip = nextIP(ip)
		if ip == nil || !ipv4Net.Contains(ip) {
			break
		}

		if !isIPAllocated(ip.String(), allocatedIPs) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no available IPs in the subnet %s", subnet)
}

func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
	return ip
}

func isIPAllocated(ip string, allocatedIPs []string) bool {
	for _, allocated := range allocatedIPs {
		if strings.HasPrefix(allocated, ip) {
			return true
		}
	}
	return false
}

func addPeer() error {
	params, err := loadParams()
	if err != nil {
		return err
	}

	allocatedIPs, err := getCurrentPeers()
	if err != nil {
		return err
	}

	ipv4, err := findNextIP(allocatedIPs, ipv4Subnet)
	if err != nil {
		return err
	}

	ipv6, err := findNextIP(allocatedIPs, ipv6Subnet)
	if err != nil {
		return err
	}

	privateKeyOut, err := execCommand(wgBinary, "genkey")
	if err != nil {
		return err
	}
	privateKey := strings.TrimSpace(string(privateKeyOut))

	publicKeyOut, err := execCommand(wgBinary, "pubkey")
	if err != nil {
		return err
	}
	publicKey := strings.TrimSpace(string(publicKeyOut))

	presharedKeyOut, err := execCommand(wgBinary, "genpsk")
	if err != nil {
		return err
	}
	presharedKey := strings.TrimSpace(string(presharedKeyOut))

	peerConf := PeerConfig{
		PrivateKey:   privateKey,
		Address:      fmt.Sprintf("%s%s, %s%s", ipv4, addressBlock, ipv6, addressBlock6),
		PresharedKey: presharedKey,
		PublicKey:    publicKey,
	}

	cmd := fmt.Sprintf(`wg set %s peer %s allowed-ips %s/32,%s/128`, params["SERVER_WG_NIC"], publicKey, ipv4, ipv6)
	_, err = execCommand("bash", "-c", cmd)
	if err != nil {
		return err
	}

	output, err := json.Marshal(peerConf)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

func deletePeer(publicKey string) error {
	params, err := loadParams()
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf(`wg set %s peer %s remove`, params["SERVER_WG_NIC"], publicKey)
	_, err = execCommand("bash", "-c", cmd)
	if err != nil {
		return err
	}

	fmt.Println("Peer deleted successfully.")
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <command> [args...]")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "add":
		if err := addPeer(); err != nil {
			log.Fatal(err)
		}
	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("Usage: wgraven delete <publickey>")
			os.Exit(1)
		}
		publicKey := os.Args[2]
		if err := deletePeer(publicKey); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}
