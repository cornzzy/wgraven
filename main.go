package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	ClientPrivateKey string `json:"clientPrivateKey"`
	Address          string `json:"address"`
	PresharedKey     string `json:"presharedKey"`
	ClientPublicKey  string `json:"clientPublicKey"`
}

type TransferInfo struct {
	Download string `json:"download"`
	Upload   string `json:"upload"`
}

func addPeer(ip string) (Peer, error) {
	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Peer{}, fmt.Errorf("generating private key: %w", err)
	}
	clientPublicKey := clientPrivateKey.PublicKey()

	psk, err := wgtypes.GenerateKey()
	if err != nil {
		return Peer{}, fmt.Errorf("generating preshared key: %w", err)
	}

	cmd := exec.Command("wg", "set", "wg0", "peer", clientPublicKey.String(), "allowed-ips", ip, "preshared-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(psk.String())
	if err := cmd.Run(); err != nil {
		return Peer{}, fmt.Errorf("adding peer: %w", err)
	}

	cmd = exec.Command("wg-quick", "save", "wg0")
	if err := cmd.Run(); err != nil {
		return Peer{}, fmt.Errorf("saving configuration: %w", err)
	}

	return Peer{
		ClientPrivateKey: clientPrivateKey.String(),
		Address:          ip,
		PresharedKey:     psk.String(),
		ClientPublicKey:  clientPublicKey.String(),
	}, nil
}

func deletePeer(clientPublicKey string) error {
	cmd := exec.Command("wg", "set", "wg0", "peer", clientPublicKey, "remove")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("removing peer: %w", err)
	}

	cmd = exec.Command("wg-quick", "save", "wg0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	return nil
}

func transfer() (map[string]TransferInfo, error) {
	cmd := exec.Command("wg", "show", "wg0", "transfer")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("getting transfer information: %w", err)
	}

	lines := strings.Split(out.String(), "\n")
	transferInfo := make(map[string]TransferInfo)

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		publicKey := parts[0]
		upload := parts[1]
		download := parts[2]

		transferInfo[publicKey] = TransferInfo{
			Download: download,
			Upload:   upload,
		}
	}

	return transferInfo, nil
}

func writeJSON(w io.Writer, v any) error {
	output, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(output))
	return err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgraven <add|delete|transfer|api> <arguments>")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "add":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven add <ip>")
			os.Exit(1)
		}
		peer, err := addPeer(os.Args[2])
		if err != nil {
			log.Fatalf("Error adding peer: %v", err)
		}
		if err := writeJSON(os.Stdout, peer); err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: wgraven delete <clientpublickey>")
			os.Exit(1)
		}
		if err := deletePeer(os.Args[2]); err != nil {
			log.Fatalf("Error deleting peer: %v", err)
		}
		fmt.Println("{\"status\": \"success\"}")
	case "transfer":
		transferInfo, err := transfer()
		if err != nil {
			log.Fatalf("Error getting transfer information: %v", err)
		}
		if err := writeJSON(os.Stdout, transferInfo); err != nil {
			log.Fatalf("Error marshalling JSON: %v", err)
		}
	case "api":
		fs := flag.NewFlagSet("api", flag.ExitOnError)
		port := fs.Int("port", 8080, "HTTPS listen port")
		quiet := fs.Bool("quiet", false, "suppress log and startup messages")
		fs.Parse(os.Args[2:])
		if err := runAPI(*port, *quiet); err != nil {
			log.Fatalf("Error running API: %v", err)
		}
	default:
		fmt.Println("Unknown command:", command)
		os.Exit(1)
	}
}
