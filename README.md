# wgraven

`wgraven` is a Go-based CLI tool for managing WireGuard peers on Debian systems. It allows you to add and remove peers, as well as retrieve transfer statistics in JSON format. The tool outputs JSON exclusively, making it suitable for integration with other tools and scripts.

## Features

- **Add a Peer**: Generate a new WireGuard peer with a private key, public key, and preshared key.
- **Delete a Peer**: Remove an existing WireGuard peer by its public key.
- **Transfer Statistics**: Retrieve current transfer statistics (download and upload) for each peer.

## Installation

1. Install Go on your system if you haven't already: [Go Installation Guide](https://golang.org/doc/install)
2. Clone the repository and build the `wgraven` binary:

    ```bash
    git clone https://github.com/cornzzy/wgraven.git
    cd wgraven
    go get
    go build
    ```


## Usage

### Add a Peer

Add a new WireGuard peer with a specified IP address.

```bash
wgraven add "<ip>"
```
Example: `wgraven add 10.25.0.2/32,fd42:42:42::2/128`

### Delete a Peer

Delete a WireGuard peer with a specified peer public key.

```bash
wgraven delete "<key>"
```
Example: `wgraven delete d8e8fca2dc0f896fd7cb4cb0031ba249d2c7c0f8e3de`

### Show transfers

Retrieve current transfer statistics for each peer.

```bash
wgraven transfer
```
Sample output
```json
{
    "wA4W3TENiDl2T8LIvVcFvyqsXU9POc3yIs4Ngv4mnGo=": {
        "download": "0",
        "upload": "0"
    },
    "1IYZ6H1XQQtH0FAPTrtKdYcU/YqYn5iVf+f44mr3IjM=": {
        "download": "43086652",
        "upload": "748127308"
    },
    "c4G6Y39MlQjkG1+wsmEOjQhb4k4GP0OxE4dNEMvqP3E=": {
        "download": "107545248",
        "upload": "1506562472"
    }
}
```

## Dependencies

To build and run `wgraven`, ensure the following dependencies are installed on your system:

- **Go**: Version 1.21 or later is required for building the project. Install it from [Go's official website](https://golang.org/doc/install).
- **wg**
- **wg-quick**
- A working wg interface named wg0
