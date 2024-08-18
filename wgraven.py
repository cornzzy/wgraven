import sys
import subprocess
import json
import ipaddress

# Define the subnets for IPv4 and IPv6
ipv4_subnet = ipaddress.ip_network('10.25.0.0/16')
ipv6_subnet = ipaddress.ip_network('fd42:42:42::/112')

def get_next_available_ip(network):
    used_ips = set()
    
    # Fetch the existing peers' IP addresses
    result = subprocess.run(['wg', 'show', 'wg0', 'allowed-ips'], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    
    for line in lines:
        parts = line.split()
        if len(parts) > 1:
            ips = parts[1:]
            for ip in ips:
                if ':' in ip:  # IPv6
                    used_ips.add(ipaddress.ip_address(ip))
                else:  # IPv4
                    used_ips.add(ipaddress.ip_address(ip))
    
    for ip in network.hosts():
        if ip not in used_ips:
            return ip
    
    raise ValueError("No available IP addresses")

def generate_keys():
    private_key = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()
    public_key = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True).stdout.strip()
    preshared_key = subprocess.run(['wg', 'genpsk'], capture_output=True, text=True).stdout.strip()
    
    return private_key, public_key, preshared_key

def add_peer():
    ipv4_address = str(get_next_available_ip(ipv4_subnet))
    ipv6_address = str(get_next_available_ip(ipv6_subnet))
    
    private_key, public_key, preshared_key = generate_keys()
    
    # Add the peer
    subprocess.run(['wg', 'set', 'wg0', 'peer', public_key, 'preshared-key', preshared_key,
                    'endpoint', 'your-endpoint-ip:port', 'allowed-ips', f'{ipv4_address}/32,{ipv6_address}/128',
                    'persistent-keepalive', '25'])
    
    response = {
        "privatekey": private_key,
        "address": f"{ipv4_address}/32, {ipv6_address}/128",
        "presharedkey": preshared_key,
        "publickey": public_key
    }
    
    print(json.dumps(response, indent=4))

def delete_peer(public_key):
    # Remove the peer
    subprocess.run(['wg', 'set', 'wg0', 'peer', public_key, 'remove'])
    print(f"Peer with public key {public_key} removed.")

def main():
    if len(sys.argv) < 2:
        print("Usage: wgraven <command> [<publickey>]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'add':
        add_peer()
    elif command == 'delete':
        if len(sys.argv) != 3:
            print("Usage: wgraven delete <publickey>")
            sys.exit(1)
        public_key = sys.argv[2]
        delete_peer(public_key)
    else:
        print("Unknown command:", command)
        sys.exit(1)

if __name__ == '__main__':
    main()
