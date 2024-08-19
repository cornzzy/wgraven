package main

import (
    "crypto/rand"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"

    "golang.zx2c4.com/wireguard/wgctrl"
    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
    "github.com/urfave/cli/v2"
)

// PeerConfig holds the configuration for the newly added peer
type PeerConfig struct {
    PrivateKey   string `json:"privateKey"`
    Address      string `json:"address"`
    PresharedKey string `json:"presharedKey"`
}

func generateKey() (wgtypes.Key, error) {
    return wgtypes.GeneratePrivateKey()
}

func generatePresharedKey() (wgtypes.Key, error) {
    return wgtypes.GenerateKey()
}

func main() {
    app := &cli.App{
        Name:  "wgraven",
        Usage: "Add a new peer to WireGuard",
        Commands: []*cli.Command{
            {
                Name:  "add",
                Usage: "Add a new peer",
                Flags: []cli.Flag{
                    &cli.StringFlag{
                        Name:     "ip",
                        Usage:    "Comma-separated IP addresses for the new peer",
                        Required: true,
                    },
                },
                Action: func(c *cli.Context) error {
                    ip := c.String("ip")

                    privateKey, err := generateKey()
                    if err != nil {
                        return cli.Exit("Failed to generate private key: "+err.Error(), 1)
                    }

                    publicKey := privateKey.PublicKey()

                    presharedKey, err := generatePresharedKey()
                    if err != nil {
                        return cli.Exit("Failed to generate preshared key: "+err.Error(), 1)
                    }

                    client, err := wgctrl.New()
                    if err != nil {
                        return cli.Exit("Failed to open wgctrl: "+err.Error(), 1)
                    }
                    defer client.Close()

                    config := PeerConfig{
                        PrivateKey:   privateKey.String(),
                        Address:      ip,
                        PresharedKey: presharedKey.String(),
                    }

                    // Update wg0.conf file
                    configFile := "/etc/wireguard/wg0.conf"
                    confData := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", publicKey.String(), presharedKey.String(), ip)
                    err = ioutil.WriteFile(configFile, []byte(confData), os.ModeAppend)
                    if err != nil {
                        return cli.Exit("Failed to write to wg0.conf: "+err.Error(), 1)
                    }

                    // Apply the new peer settings using wgctrl
                    err = client.ConfigureDevice("wg0", wgtypes.Config{
                        Peers: []wgtypes.PeerConfig{
                            {
                                PublicKey:    publicKey,
                                PresharedKey: &presharedKey,
                                AllowedIPs: []wgtypes.IPNet{
                                    {IP: parseCIDR(ip)},
                                },
                            },
                        },
                    })
                    if err != nil {
                        return cli.Exit("Failed to configure wg0 device: "+err.Error(), 1)
                    }

                    output, err := json.Marshal(config)
                    if err != nil {
                        return cli.Exit("Failed to marshal JSON: "+err.Error(), 1)
                    }

                    fmt.Println(string(output))
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

// parseCIDR parses a CIDR string into a net.IPNet
func parseCIDR(cidr string) wgtypes.IPNet {
    ip, network, err := net.ParseCIDR(cidr)
    if err != nil {
        log.Fatalf("Failed to parse CIDR: %v", err)
    }
    return wgtypes.IPNet{
        IP:   ip,
        Mask: network.Mask,
    }
}
