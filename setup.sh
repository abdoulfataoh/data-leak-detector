#!/bin/bash

sudo apt update
sudo apt-get install hostpad
sudo apt-get install tshark
mkdir packets
chown root:root packets
echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_Testing/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_Testing/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek
