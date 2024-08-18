package main

import (
	"bufio"
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
)

func findNextIP(usedIPs []string, subnet string) (string, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}

	ip := ipnet.IP
	for {
		ip = incrementIP(ip)
		if !ipnet.Contains(ip) {
			break
		}
		ipStr := ip.String()
		if !contains(usedIPs, ipStr) {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("no available IPs in subnet %s", subnet)
}

func incrementIP(ip net.IP) net.IP {
	ip = ip.To16()
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
	return ip
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
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

	ipv4s := []string{}
	ipv6s := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			ipv4 := strings.Split(fields[1], "/")[0]
			ipv6 := strings.Split(fields[2], "/")[0]
			ipv4s = append(ipv4s, ipv4)
			ipv6s = append(ipv6s, ipv6)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return ipv4s, ipv6s, nil
}

func addPeer() error {
	ipv4s, ipv6s, err := getUsedIPs()
	if err != nil {
		return err
	}

	nextIPv4, err := findNextIP(ipv4s, ipv4Subnet)
	if err != nil {
		return err
	}

	nextIPv6, err := findNextIP(ipv6s, ipv6Subnet)
	if err != nil {
		return err
	}

	fmt.Printf("Next available IPv4: %s\n", nextIPv4)
	fmt.Printf("Next available IPv6: %s\n", nextIPv6)

	// Add your logic to generate peer configuration and add it to WireGuard here.
	// For now, let's just print the IPs for demo purposes.

	return nil
}

func deletePeer(publicKey string) error {
	cmd := exec.Command("wg", "set", wgInterface, "peer", publicKey, "remove")
	err := cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("wg", "syncconf", wgInterface, fmt.Sprintf("<(wg-quick strip %s)", wgInterface))
	err = cmd.Run()
	if err != nil {
		return err
	}

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
