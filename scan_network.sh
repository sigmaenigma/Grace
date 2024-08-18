#!/bin/bash

# Function to check if jq is installed
check_jq() {
    if ! command -v jq &> /dev/null; then
        echo "jq is not installed and required to run this script."
        read -p "Would you like to install jq? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            echo "Installing jq..."
            sudo apt update
            sudo apt install -y jq
            if [ $? -eq 0 ]; then
                echo "jq installed successfully."
            else
                echo "Failed to install jq. Please install it manually."
                exit 1
            fi
        else
            echo "jq is required to run this script. Exiting."
            exit 1
        fi
    fi
}

# Check if jq is installed
check_jq

# Read network ranges from config.json
network_ranges=$(jq -r '.network_ranges[]' config.json)

# Create or clear the output file
> ip_addresses.txt

# Use nmap to scan the networks and list the IP addresses
echo "Starting network scan..."
for network_range in $network_ranges; do
    nmap -sn $network_range -oG - | awk '/Up$/{print $2}' | while read ip; do
        echo "Found active IP: $ip"
        echo "\"$ip\"" >> ip_addresses.txt
    done
done

echo "Network scan completed. IP addresses saved to ip_addresses.txt."
