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

# Create a full backup of the current resolved.conf BEFORE changing anything.
# -a preserves permissions/ownership/timestamps (good for restoring safely).
# Appends today’s date (YYYY-MM-DD) so you can keep multiple backups.
cp -a /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak.$(date +%F)

# Open the config file in an editor to make persistent DNS resolver changes.
# Security note: editing directly works, but a drop-in file is usually cleaner/safer long-term.
nano /etc/systemd/resolved.conf

```

3. add/update these values in the file:
```ini
# This section defines settings for systemd-resolved’s resolver behavior.
[Resolve]

# Disable LLMNR (Link-Local Multicast Name Resolution).
# Security-wise: reduces risk of local-network name spoofing/poisoning attacks
# (LLMNR is often abused on LANs to trick machines into authenticating to attackers).
LLMNR=no

# Disable Multicast DNS (mDNS / “Bonjour” style local discovery).
# Security-wise: reduces local discovery + spoofing surface; servers usually don’t need mDNS.
MulticastDNS=no
```

4. 
```bash

# Restart the resolver service so the new configuration takes effect immediately.
# Security-wise: ensures you’re actually running with the hardened settings (not “pending changes”).
systemctl restart systemd-resolved

# Show current service status and recent logs (without paging).
# Security-wise: confirms it restarted cleanly and helps catch config errors right away.
systemctl status systemd-resolved --no-pager
```

### Remove monarx-agent


```bash
# Stop the Monarx agent service right now.
# Security-wise: immediately halts its running daemon (no more active monitoring/changes/network activity).
systemctl stop monarx-agent

# Disable the Monarx agent from starting automatically on boot.
# Security-wise: prevents it from reappearing after reboot (common persistence mechanism).
systemctl disable monarx-agent

# Purge Monarx packages and their config files (stronger than "remove").
# Security-wise: ensures service configs, unit files, and package-owned settings are deleted (reduces persistence).
apt -y purge monarx-agent monarx-protect monarx-protect-autodetect

# Remove unused dependencies that were installed only for Monarx.
# Security-wise: reduces attack surface by removing extra libraries/tools you no longer need.
apt -y autoremove --purge

# Clean old cached .deb packages from APT.
# Security-wise: mostly hygiene; reduces clutter and removes stale cached installers (not a major security step).
apt -y autoclean

# Check if any Monarx processes are still running.
# Security-wise: verifies the agent truly stopped (malware/agents sometimes restart via another supervisor).
pgrep -a monarx || echo "OK: no monarx processes running"

# Inspect systemd unit status.
# Security-wise: confirms whether the service is gone/disabled or if something is still managing it.
# Note: if the unit is removed, you'll typically see "Unit monarx-agent.service could not be found."
systemctl status monarx-agent --no-pager

# Confirm no Monarx-related ports are listening (example ports shown).
# Security-wise: ensures the agent isn’t exposing local/remote listeners that could be abused.
ss -tulpn | grep -E 'monarx|:1721|:65529' || echo "OK: no monarx ports are listening"

# List extra APT repository definition files.
# Security-wise: third-party repos can re-install packages or introduce supply-chain risk—good to audit.
ls -al /etc/apt/sources.list.d/

# Search APT sources for any Monarx repo entries.
# Security-wise: ensures you’re not leaving a repo behind that could reinstall Monarx on future upgrades.
grep -R "monarx" -n /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || echo "OK: no monarx apt entries found"

# Remove the Monarx repository file if it exists.
# Security-wise: prevents APT from fetching Monarx packages again from that source.
rm -f /etc/apt/sources.list.d/monarx.list

# Refresh APT package index after repo changes.
# Security-wise: ensures your package lists reflect the current trusted repositories only.
apt update

# Confirm no Monarx packages remain installed.
# Security-wise: double-verifies the software is fully removed (no leftover packages).
dpkg -l | grep -i monarx || echo "OK: no monarx packages installed"

# Double-check again for running processes by name.
# Security-wise: catches edge cases where something respawned after package removal.
pgrep -a monarx || echo "OK: no monarx processes running"

# Double-check listening ports again.
# Security-wise: ensures nothing is bound to those ports after cleanup (good final validation step).
ss -tulpn | grep -Ei 'monarx|:1721|:65529' || echo "OK: no monarx ports listening"

# List “human” users (UID >= 1000) excluding nobody, with home + shell.
# Security-wise: helps detect suspicious/unauthorized user accounts that could have been created for persistence.
awk -F: '($3>=1000)&&($1!="nobody"){print $1" uid="$3" home="$6" shell="$7}' /etc/passwd
```

### SSH
```bash
# Confirm you are root on the VPS before doing user/system changes.
# Security: avoids permission issues + prevents half-applied config changes.
whoami

# Create a dedicated non-root admin user, set a strong password (even if you disable SSH passwords later).
# Security: least-privilege—reduces risk vs logging in as root.
adduser [uname]  # 

# Add the user to sudo group so they can administer without using root directly.
# Security: privilege separation + sudo logs who did what.
usermod -aG sudo [uname]

# Verify group membership.
# Security: confirms the user can admin before you disable root login.
id [uname]  # Expected: includes sudo
```

```powershell
# Generate a modern Ed25519 keypair with stronger KDF rounds (-a 64) to protect the private key at rest.
# Security: key-based auth is far more resistant to brute-force than passwords.
ssh-keygen -t ed25519 -a 64 -f $env:USERPROFILE\.ssh\[filename] -C "[uname]@ekar"

```
```powershell
# Print the public key so you can copy it to the server.
# Security: you ONLY share the .pub key—never the private key.
type $env:USERPROFILE\.ssh\ekardeploy.pub

```

```bash
# Create .ssh directory if missing.
# Security: SSH will ignore unsafe key files/dirs; correct setup prevents lockouts and avoids accidental exposure.
mkdir -p /home/ekardeploy/.ssh

# Set directory permissions (owner full access only).
# Security: prevents other users from reading/modifying SSH configuration.
chmod 700 /home/ekardeploy/.ssh

# Create authorized_keys file (where allowed public keys live).
touch /home/ekardeploy/.ssh/authorized_keys

# Set file permissions (owner read/write only).
# Security: prevents key tampering or disclosure; SSH may refuse insecure perms.
chmod 600 /home/ekardeploy/.ssh/authorized_keys

# Ensure the user owns the directory and file.
# Security: prevents privilege confusion and SSH refusing the key due to ownership.
chown -R ekardeploy:ekardeploy /home/ekardeploy/.ssh

# Paste the public key into authorized_keys.
# Security: this enables key-only access for that user.
nano /home/ekardeploy/.ssh/authorized_keys
```
```bash

# Re-apply ownership and permissions as a sanity check.
# Security: avoids “bad ownership or modes” errors and prevents accidentally open perms.
chown -R ekardeploy:ekardeploy /home/ekardeploy/.ssh
chmod 700 /home/ekardeploy/.ssh
chmod 600 /home/ekardeploy/.ssh/authorized_keys

```
```powershell
# Remove old host key entry for the IP.
# Security: prevents connecting while your laptop still distrusts the server; use this after rebuild/reinstall.
ssh-keygen -R 85.209.95.66

# Test SSH login using your key.
# Security: ALWAYS confirm key login works in a NEW session before disabling password/root login.
ssh -i $env:USERPROFILE\.ssh\KEY_NAME -o IdentitiesOnly=yes ADMIN_USER@YOUR_VPS_IP

```
```bash
# Backup sshd_config with timestamp.
# Security: fast rollback if you lock yourself out.
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F_%H%M%S)

# Confirm backups exist.
ls -al /etc/ssh/sshd_config*

# Edit a drop-in file (cleaner than editing the main config).
# Security: reduces conflicts with package updates and cloud-init defaults.
nano /etc/ssh/sshd_config.d/99-hardening.conf

```
```ini
# =========================
# SSH Hardening (Debian 12)
# =========================

# Use SSH protocol 2 only (modern)
Protocol 2

# Only allow this specific user to SSH.
# Security: blocks all other accounts even if they exist or get created later.
AllowUsers ekardeploy

# Disable direct root login.
# Security: attackers commonly target root; forces least-privilege access.
PermitRootLogin no

# Enforce key-based auth only.
# Security: eliminates password brute-force and credential stuffing risk.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no

# Limit brute-force and abuse.
# Security: reduces guessing attempts and resource exhaustion.
MaxAuthTries 3
LoginGraceTime 20
MaxSessions 5
MaxStartups 10:30:60

# Reduce attack surface.
# Security: disables features that are frequently abused or not needed on servers.
X11Forwarding no
AllowAgentForwarding no

# WARNING: This can break VS Code Remote-SSH and any port forwarding you use.
# Security: disabling forwarding reduces lateral movement/exfil routes.
AllowTcpForwarding no

PermitTunnel no
PermitUserEnvironment no

# Drop dead sessions.
# Security: reduces long-lived hijacked sessions and cleans up zombie connections.
ClientAliveInterval 300
ClientAliveCountMax 2

# More detailed logs.
# Security: better investigation/auditing (at the cost of slightly noisier logs).
LogLevel VERBOSE
```

```bash
# You’re checking cloud-init’s SSH override file.
# Security: cloud-init can re-enable password auth; you MUST ensure it’s not undoing your hardening.
nano /etc/ssh/sshd_config.d/50-cloud-init.conf
```
```ini
# You’re ensuring password auth is disabled there too.
# Security: avoids cloud-init overriding your drop-in in some setups.
PasswordAuthentication no
```
```bash
# Search all ssh configs for password auth directives.
# Security: “source of truth” is effective config; this finds conflicts/duplicates.
grep -Rni 'PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf

# Tell cloud-init not to allow SSH password auth.
# Security: prevents it from re-enabling passwords on reboot/provision events.
nano /etc/cloud/cloud.cfg.d/99-disable-ssh-passwords.cfg
```
```ini
ssh_pwauth: false
```
```bash# Test sshd configuration syntax BEFORE reloading.
# Security: prevents pushing a broken config that could lock you out.
sshd -t

# Expect 0 (success).
echo $?

# Reload (safer than restart).
# Security: reload applies changes without killing existing SSH sessions.
systemctl reload ssh

# Confirm ssh is healthy.
systemctl status ssh --no-pager

# Show effective settings.
# Security: confirms what sshd is ACTUALLY using (not just what files say).
sshd -T | egrep -i 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|allowusers'

```
```powershell
ssh root@YOUR_VPS_IP #should be blocked
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no ADMIN_USER@YOUR_VPS_IP #should be blocked
ssh -i $env:USERPROFILE\.ssh\KEY_NAME -o IdentitiesOnly=yes ADMIN_USER@YOUR_VPS_IP

```
