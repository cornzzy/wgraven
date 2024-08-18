package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "os/exec"
    "strings"
    "net"
    "crypto/rand"
    "encoding/base64"
    "github.com/google/uuid"
)

const (
    wgInterface = "wg0"
    ipv4Subnet   = "10.25.0.0/16"
    ipv6Subnet   = "fd42:42:42::0/112"
)

type Peer struct {
    PublicKey       string `json:"publickey"`
    PrivateKey      string `json:"privatekey"`
    Address         string `json:"address"`
    PresharedKey    string `json:"presharedkey"`
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: wgraven <command> [arguments]")
        os.Exit(1)
    }

    switch os.Args[1] {
    case "add":
        addPeer()
    case "delete":
        if len(os.Args) != 3 {
            fmt.Println("Usage: wgraven delete <publickey>")
            os.Exit(1)
        }
        deletePeer(os.Args[2])
    default:
        fmt.Println("Unknown command:", os.Args[1])
        os.Exit(1)
    }
}

func addPeer() {
    ipv4Address, ipv6Address, err := findNextAvailableIPs()
    if err != nil {
        fmt.Println("Error finding available IPs:", err)
        os.Exit(1)
    }

    privateKey, err := generateKey()
    if err != nil {
        fmt.Println("Error generating private key:", err)
        os.Exit(1)
    }

    publicKey, err := generatePublicKey(privateKey)
    if err != nil {
        fmt.Println("Error generating public key:", err)
        os.Exit(1)
    }

    presharedKey, err := generateKey()
    if err != nil {
        fmt.Println("Error generating preshared key:", err)
        os.Exit(1)
    }

    err = addPeerToConfig(publicKey, privateKey, presharedKey, ipv4Address, ipv6Address)
    if err != nil {
        fmt.Println("Error adding peer to configuration:", err)
        os.Exit(1)
    }

    peer := Peer{
        PublicKey:    publicKey,
        PrivateKey:   privateKey,
        Address:      fmt.Sprintf("%s, %s", ipv4Address, ipv6Address),
        PresharedKey: presharedKey,
    }

    output, err := json.MarshalIndent(peer, "", "  ")
    if err != nil {
        fmt.Println("Error marshalling JSON:", err)
        os.Exit(1)
    }

    fmt.Println(string(output))
}

func deletePeer(publicKey string) {
    err := removePeerFromConfig(publicKey)
    if err != nil {
        fmt.Println("Error deleting peer from configuration:", err)
        os.Exit(1)
    }

    fmt.Println("Peer deleted successfully.")
}

func findNextAvailableIPs() (string, string, error) {
    // List all existing peers
    cmd := exec.Command("wg", "show", wgInterface, "allowed-ips")
    output, err := cmd.Output()
    if err != nil {
        return "", "", err
    }

    existingIPs := parseIPAddresses(string(output))
    nextIPv4, nextIPv6 := nextIP(existingIPs)

    if nextIPv4 == "" || nextIPv6 == "" {
        return "", "", fmt.Errorf("could not find available IPs")
    }

    return nextIPv4, nextIPv6, nil
}

func parseIPAddresses(output string) map[string]struct{} {
    existingIPs := make(map[string]struct{})
    lines := strings.Split(output, "\n")

    for _, line := range lines {
        if len(line) == 0 {
            continue
        }
        parts := strings.Fields(line)
        if len(parts) > 1 {
            ipAddresses := strings.Split(parts[1], ",")
            for _, ip := range ipAddresses {
                existingIPs[ip] = struct{}{}
            }
        }
    }

    return existingIPs
}

func nextIP(existingIPs map[string]struct{}) (string, string) {
    ipv4Addr, ipv6Addr := findNextIPv4(existingIPs), findNextIPv6(existingIPs)
    return ipv4Addr, ipv6Addr
}

func findNextIPv4(existingIPs map[string]struct{}) string {
    subnet := net.IPNet{
        IP:   net.ParseIP("10.25.0.0"),
        Mask: net.CIDRMask(16, 32),
    }

    for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); incrementIP(ip) {
        if _, exists := existingIPs[ip.String()]; !exists {
            return ip.String() + "/32"
        }
    }

    return ""
}

func findNextIPv6(existingIPs map[string]struct{}) string {
    subnet := net.IPNet{
        IP:   net.ParseIP("fd42:42:42::"),
        Mask: net.CIDRMask(112, 128),
    }

    for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); incrementIP(ip) {
        if _, exists := existingIPs[ip.String()]; !exists {
            return ip.String() + "/128"
        }
    }

    return ""
}

func incrementIP(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] != 0 {
            break
        }
    }
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
    output, err := cmd.Output()
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(output)), nil
}

func addPeerToConfig(publicKey, privateKey, presharedKey, ipv4, ipv6 string) error {
    cmd := exec.Command("wg", "set", wgInterface,
        "peer", publicKey,
        "preshared-key", presharedKey,
        "endpoint", "YOUR_SERVER_IP:51820",
        "allowed-ips", ipv4, ipv6,
    )
    return cmd.Run()
}

func removePeerFromConfig(publicKey string) error {
    cmd := exec.Command("wg", "set", wgInterface, "peer", publicKey, "remove")
    return cmd.Run()
}
