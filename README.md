### Setting up the VPS
```bash
# Show OS release details (important to confirm you’re on the expected distro/version
# so you apply the right hardening steps and security guidance for Debian 12).
cat /etc/os-release

# Show kernel + arch (security-wise: confirms you’re running a modern kernel and helps
# verify you actually rebooted into a patched kernel after upgrades).
uname -a

# Refresh APT package lists (security-wise: you can’t reliably install security fixes
# or verify “latest” versions without up-to-date package indexes).
apt update

# Upgrade everything (security-wise: closes known vulnerabilities in installed packages;
# full-upgrade also handles dependency changes that sometimes carry security fixes).
apt -y full-upgrade

# Remove unused packages (security-wise: fewer packages = smaller attack surface;
# purging configs can remove old/unsafe leftovers).
apt -y autoremove --purge

# Clean old cached packages (security-wise: reduces disk usage and removes stale packages;
# not a huge “security” step, but keeps the system tidy and less error-prone).
apt -y autoclean

# Set timezone (security-wise: correct timestamps matter for auditing, incident response,
# fail2ban bans, log correlation, and forensics).
sudo timedatectl set-timezone America/New_York

# Verify time + NTP status (security-wise: accurate time prevents messy logs and helps
# security tools work correctly; wrong time can break TLS validation and monitoring).
timedatectl

# Check time sync service (security-wise: consistent time helps log integrity, alerting,
# certificate validation, and troubleshooting weird auth/security issues).
systemctl status systemd-timesyncd --no-pager

# Install sudo (security-wise: lets you stop using root directly; supports least-privilege
# admin and audit trails (who ran what) via sudo logs).
apt -y install sudo

# Install curl (security-wise: needed to fetch repository keys, verify endpoints,
# test HTTPS/TLS, and pull security tooling/scripts from trusted sources).
apt -y install curl

# Install wget (security-wise: similar to curl—useful for downloading updates/files;
# choose trusted sources and verify hashes/signatures when possible).
apt -y install wget

# Install CA certificates (security-wise: enables proper TLS verification for HTTPS;
# without this, downloads/APIs may fail or people may bypass verification—dangerous).
apt -y install ca-certificates

# Install GnuPG (security-wise: you can verify signed repositories and packages;
# prevents “trust me bro” installs and helps avoid tampered software).
apt -y install gnupg2

# Install lsb-release (security-wise: many official install scripts detect distro/version;
# reduces the chance of running the wrong commands that weaken security).
apt -y install lsb-release

# Install UFW firewall manager (security-wise: a firewall is a primary layer of defense;
# you explicitly allow only required ports (e.g., 22/80/443) and block everything else).
apt -y install ufw

# Install Fail2ban (security-wise: mitigates brute-force attacks by banning IPs after
# repeated login failures—especially important for SSH exposed to the internet).
apt -y install fail2ban

# Install unattended-upgrades (security-wise: automatically applies security patches
# so you’re not exposed for weeks because you forgot to update).
apt -y install unattended-upgrades

# Install apt-listchanges (security-wise: shows important package change notices;
# helps you spot security-relevant behavior changes, service restarts, or warnings).
apt -y install apt-listchanges

# Install vim-tiny (security-wise: you’ll edit config files frequently; having a reliable
# editor reduces mistakes that accidentally open services or weaken configs).
apt -y install vim-tiny

# Install nano (security-wise: same reason—quick safe edits; fewer “I’ll do it later”
# delays when you need to change a critical config right now).
apt -y install nano

# Install less (security-wise: safely view long configs/logs without altering them;
# helpful for reviewing sshd_config, nginx configs, fail2ban logs, etc.).
apt -y install less

# Install htop (security-wise: helps you spot suspicious processes, high CPU miners,
# unknown services, and unusual resource usage quickly).
apt -y install htop

# Install iotop (security-wise: ransomware/malware often causes heavy disk writes;
# iotop helps detect abnormal disk activity and the responsible process).
apt -y install iotop

# Install iftop (security-wise: helps detect unexpected outbound traffic (data exfiltration),
# command-and-control traffic, or weird connections).
apt -y install iftop

# Install net-tools (security-wise: legacy tools; not required, but sometimes useful for
# troubleshooting. Prefer iproute2/ss; keeping extras minimal reduces attack surface slightly).
apt -y install net-tools

# Install iproute2 (security-wise: modern, maintained networking tools; needed to inspect
# routes, interfaces, and sockets accurately (critical for exposure checks)).
apt -y install iproute2

# Install dnsutils (security-wise: helps verify DNS, troubleshoot hijacks/misconfig,
# and validate domain resolution for your services and SSL certificates).
apt -y install dnsutils

# Install lsof (security-wise: identify which process is bound to a port or holding a file;
# great for tracking unknown listeners or suspicious file locks).
apt -y install lsof

# Install psmisc (security-wise: tools like pstree help visualize process trees (spot malware
# chains); killall/fuser help safely stop rogue processes or services).
apt -y install psmisc

# Install rsyslog (security-wise: strengthens logging options; you can forward logs to another
# server later (centralized logs help detect tampering and preserve evidence)).
apt -y install rsyslog

# Install logrotate (security-wise: prevents logs from filling disk (DoS risk) and keeps
# logs manageable for auditing; ensures old logs are archived/rotated correctly).
apt -y install logrotate

# Install OpenSSH server (security-wise: required for remote administration; once installed,
# you must harden it (keys only, disable root login, limit users, etc.)).
apt -y install openssh-server

# Enable and start SSH (security-wise: makes remote access reliable; BUT you should ensure
# firewall rules and ssh hardening are applied to reduce attack exposure).
systemctl enable --now ssh

# Check SSH status (security-wise: verify it’s running as expected and not failing due to
# config errors—misconfigurations can cause you to “open up” unsafe quick fixes).
systemctl status ssh --no-pager

# List listening ports + owning processes (security-wise: confirms what’s actually exposed
# to the network; you want the smallest possible list—usually just SSH + web ports).
ss -tulpn

```

### Disable LLMNR / mDNS (remove port 5355 exposure)


```bash

echo -e "\e[32ms35######\\e[0m" && cp -a /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak.$(date +%F) && echo -e "\e[31me35######\\e[0m" && echo #backup the config.
echo -e "\e[32ms36######\\e[0m" && nano /etc/systemd/resolved.conf && echo -e "\e[31me36######\\e[0m" && echo #edit the config file.

```

3. add/update these values in the file:
```ini
[Resolve]
LLMNR=no
MulticastDNS=no
```

4. 
```bash
echo -e "\e[32ms37######\\e[0m" && systemctl restart systemd-resolved && echo -e "\e[31me37######\\e[0m" && echo #restart applies the new settings.
echo -e "\e[32ms38######\\e[0m" && systemctl status systemd-resolved --no-pager && echo -e "\e[31me38######\\e[0m" && echo #status confirms it restarted cleanly (no errors).
```

### Remove monarx-agent


```bash
systemctl stop monarx-agent #immediately stops the running process (/usr/bin/monarx-agent).
systemctl disable monarx-agent #removes the “start at boot” symlinks.
apt -y purge monarx-agent monarx-protect monarx-protect-autodetect #removes the packages and their configuration files.
apt -y autoremove --purge #cleanup unused deps.
apt -y autoclean #cleanup old packages.
pgrep -a monarx || echo "OK: no monarx processes running" #confirm no process exists.
systemctl status monarx-agent --no-pager #confirm systemd unit no longer exists.
ss -tulpn | grep -E 'monarx|:1721|:65529' || echo "OK: no monarx ports are listening" #confirm those loopback ports disappeared.
ls -al /etc/apt/sources.list.d/ #check for Monarx apt repo if it exists.
grep -R "monarx" -n /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || echo "OK: no monarx apt entries found" #confirm no monarx apt entries exist.
rm -f /etc/apt/sources.list.d/monarx.list #remove monarx list if present.
apt update #refresh package index.
dpkg -l | grep -i monarx || echo "OK: no monarx packages installed" #confirm no monarx packages installed.
pgrep -a monarx || echo "OK: no monarx processes running" # double-check no monarx processes.
ss -tulpn | grep -Ei 'monarx|:1721|:65529' || echo "OK: no monarx ports listening" #double-check no monarx ports listening.
awk -F: '($3>=1000)&&($1!="nobody"){print $1" uid="$3" home="$6" shell="$7}' /etc/passwd #check for weird users (uid >= 1000 excluding nobody).
```

### SSH
```bash
whoami #Expected: root
```

```bash
adduser [uname] #set a password (use a strong one) , optionally fill in name/info (can be blank)
```

```bash
usermod -aG sudo [uname] #grant admin rights
id [uname] #Expected: output includes sudo in groups.
```

```powershell
ssh-keygen -t ed25519 -a 64 -f $env:USERPROFILE\.ssh\[filename] -C "[uname]@ekar"

```
```powershell
type $env:USERPROFILE\.ssh\ekardeploy.pub

```

```bash
mkdir -p /home/ekardeploy/.ssh
chmod 700 /home/ekardeploy/.ssh
touch /home/ekardeploy/.ssh/authorized_keys
chmod 600 /home/ekardeploy/.ssh/authorized_keys
chown -R ekardeploy:ekardeploy /home/ekardeploy/.ssh
```
```bash
nano /home/ekardeploy/.ssh/authorized_keys #paste the key
```
```bash
#Now re-apply perms (quick sanity re-check):
chown -R ekardeploy:ekardeploy /home/ekardeploy/.ssh
chmod 700 /home/ekardeploy/.ssh
chmod 600 /home/ekardeploy/.ssh/authorized_keys

```
```powershell
ssh-keygen -R 85.209.95.66
ssh -i $env:USERPROFILE\.ssh\KEY_NAME -o IdentitiesOnly=yes ADMIN_USER@YOUR_VPS_IP #Laptop: test SSH login using the key
```
```bash
#VPS: backup current SSH config
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F_%H%M%S)
ls -al /etc/ssh/sshd_config*
#VPS: create a hardening drop-in file (recommended method)
nano /etc/ssh/sshd_config.d/99-hardening.conf
```
```ini
# =========================
# SSH Hardening (Debian 12)
# =========================

# Use SSH protocol 2 only (modern)
Protocol 2

# Only allow this user to SSH (tight access control)
AllowUsers ekardeploy

# Disable direct root login over SSH
PermitRootLogin no

# Key-based auth only (disable passwords and interactive auth)
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no

# Reduce brute-force effectiveness
MaxAuthTries 3
LoginGraceTime 20
MaxSessions 5
MaxStartups 10:30:60

# Reduce attack surface
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no

# Keep sessions healthy & kill dead ones
ClientAliveInterval 300
ClientAliveCountMax 2

# Better logging for investigations
LogLevel VERBOSE
```

```bash
nano /etc/ssh/sshd_config.d/50-cloud-init.conf
```
```ini
PasswordAuthentication no
```
```bash
grep -Rni 'PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf #Cloud-init warning (VERY IMPORTANT)

nano /etc/cloud/cloud.cfg.d/99-disable-ssh-passwords.cfg
```
```ini
ssh_pwauth: false
```
```bash
sshd -t
echo $? #expected 0
systemctl reload ssh
systemctl status ssh --no-pager
sshd -T | egrep -i 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|allowusers' #Confirm the effective SSH config (source of truth)
```
```powershell
ssh root@YOUR_VPS_IP #should be blocked
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no ADMIN_USER@YOUR_VPS_IP #should be blocked
ssh -i $env:USERPROFILE\.ssh\KEY_NAME -o IdentitiesOnly=yes ADMIN_USER@YOUR_VPS_IP

```
