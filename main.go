package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/urfave/cli/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	wgConfigFile  = "/etc/wireguard/wg0.conf"
)

type PeerInfo struct {
	PrivateKey   string `json:"privateKey"`
	Address      string `json:"address"`
	PresharedKey string `json:"presharedKey"`
}

func main() {
	app := &cli.App{
		Name:  "wgraven",
		Usage: "Manage WireGuard peers",
		Commands: []*cli.Command{
			{
				Name:   "add",
				Usage:  "Add a new peer to WireGuard",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "ip",
						Usage:    "IP address to assign to the new peer (e.g., '10.8.0.2/32,fd42:42:42::2/128')",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					ip := c.String("ip")
					peerInfo, err := addPeer(ip)
					if err != nil {
						fmt.Println(`{"error": "` + err.Error() + `"}`)
						return nil
					}
					// Output peer info as JSON
					peerInfoJSON, err := json.Marshal(peerInfo)
					if err != nil {
						return fmt.Errorf("failed to marshal peer info: %w", err)
					}
					fmt.Println(string(peerInfoJSON))
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func addPeer(ip string) (*PeerInfo, error) {
	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	peerPublicKey := peerPrivateKey.PublicKey()

	preSharedKey, err := generatePSK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-shared key: %w", err)
	}

	// Add the new peer to wg0.conf
	peerConfig := fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
`, peerPublicKey.String(), preSharedKey, ip)

	if err := appendToFile(wgConfigFile, peerConfig); err != nil {
		return nil, fmt.Errorf("failed to append peer config to wg0.conf: %w", err)
	}

	// Apply the new peer configuration using `wg` command
	err = exec.Command("wg", "set", "wg0", "peer", peerPublicKey.String(), "allowed-ips", ip).Run()
	if err != nil {
		return nil, fmt.Errorf("failed to set peer: %w", err)
	}

	return &PeerInfo{
		PrivateKey:   peerPrivateKey.String(),
		Address:      ip,
		PresharedKey: preSharedKey,
	}, nil
}

func generatePSK() (string, error) {
	key := make([]byte, wgtypes.KeyLen)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate pre-shared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func appendToFile(filename, text string) error {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(text); err != nil {
		return err
	}
	return nil
}
