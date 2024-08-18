package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	wgInterface = "wg0"
	configFile  = "/etc/wireguard/wg0.conf"
	ipv4Subnet  = "10.25.0.0/16"
	ipv6Subnet  = "fd42:42:42::0/112"
	serverIPv4  = "10.25.0.1/32"
	serverIPv6  = "fd42:42:42::1/128"
)

func findNextIP(ipRange string, usedIPs []string, skipIP string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return "", err
	}

	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ipStr := ip.String()
		if ipStr == skipIP || contains(usedIPs, ipStr) {
			continue
		}
		return ipStr, nil
	}

	return "", fmt.Errorf("no available IPs in range %s", ipRange)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getUsedIPs() ([]string, []string, error) {
	cmd := exec.Command("wg", "show", wgInterface, "allowed-ips")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, err
	}

	var usedIPv4s, usedIPv6s []string
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			usedIPv4s = append(usedIPv4s, strings.Split(parts[1], "/")[0])
			if len(parts) >= 3 {
				usedIPv6s = append(usedIPv6s, strings.Split(parts[2], "/")[0])
			}
		}
	}

	return usedIPv4s, usedIPv6s, nil
}

func addPeer() error {
	usedIPv4s, usedIPv6s, err := getUsedIPs()
	if err != nil {
		return err
	}

	nextIPv4, err := findNextIP(ipv4Subnet, usedIPv4s, "10.25.0.1")
	if err != nil {
		return err
	}

	nextIPv6, err := findNextIP(ipv6Subnet, usedIPv6s, "fd42:42:42::1")
	if err != nil {
		return err
	}

	fmt.Printf("Next IPv4: %s/32, Next IPv6: %s/128\n", nextIPv4, nextIPv6)

	// Add the peer to wg0.conf (this step requires admin privileges)
	// This is a placeholder. In a real application, you'd need to use a keypair generator
	// and dynamically build the peer configuration.
	peerConfig := fmt.Sprintf(`
[Peer]
# Add your new peer configuration here
AllowedIPs = %s/32, %s/128
`, nextIPv4, nextIPv6)

	cmd := exec.Command("wg", "set", wgInterface, "peer", "NEW_PUBLIC_KEY", "allowed-ips", fmt.Sprintf("%s/32", nextIPv4), fmt.Sprintf("%s/128", nextIPv6))
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("wg-quick", "strip", wgInterface)
	cmd.Stdin = bytes.NewBufferString(peerConfig)
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("wg", "syncconf", wgInterface, fmt.Sprintf("<(wg-quick strip %s)", wgInterface))
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("Peer added successfully.")
	return nil
}

func deletePeer(publicKey string) error {
	cmd := exec.Command("wg", "set", wgInterface, "peer", publicKey, "remove")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("wg-quick", "strip", wgInterface)
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("wg", "syncconf", wgInterface, fmt.Sprintf("<(wg-quick strip %s)", wgInterface))
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("Peer deleted successfully.")
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven add | delete <publickey>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "add":
		err := addPeer()
		if err != nil {
			fmt.Println("Error adding peer:", err)
		}
	case "delete":
		if len(os.Args) != 3 {
			fmt.Println("Usage: wgraven delete <publickey>")
			os.Exit(1)
		}
		err := deletePeer(os.Args[2])
		if err != nil {
			fmt.Println("Error deleting peer:", err)
		}
	default:
		fmt.Println("Usage: wgraven add | delete <publickey>")
		os.Exit(1)
	}
}
