#!/bin/bash
# Configure SSH for password authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl restart sshd

# Create honeypot users
useradd -m -s /bin/bash admin 2>/dev/null || true
useradd -m -s /bin/bash user 2>/dev/null || true
useradd -m -s /bin/bash test 2>/dev/null || true
echo 'admin:password' | chpasswd
echo 'user:password123' | chpasswd
echo 'test:test' | chpasswd
echo 'root:password' | chpasswd

# Install monitoring tools
apt-get update
apt-get install -y inotify-tools awscli

# Setup file upload monitor
cat > /usr/local/bin/monitor-uploads.sh << 'SCRIPT'
#!/bin/bash
WATCH_DIR="/home"
S3_BUCKET="honeypot-malware-1765297098"

inotifywait -m -r -e create,moved_to --format '%w%f' "$WATCH_DIR" | while read FILE
do
    if [[ "$FILE" == *"/ubuntu/"* ]] || [[ "$FILE" == *"/.ssh/"* ]]; then
        continue
    fi
    sleep 2
    aws s3 cp "$FILE" "s3://$S3_BUCKET/captured/$(basename $FILE)" 2>&1
done
SCRIPT

chmod +x /usr/local/bin/monitor-uploads.sh

# Create systemd service
cat > /etc/systemd/system/honeypot-monitor.service << 'SERVICE'
[Unit]
Description=Honeypot File Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/monitor-uploads.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable honeypot-monitor
systemctl start honeypot-monitor
