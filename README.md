<details>
<summary>Prepare VPS</summary>

# Prepare VPS (Debian 12) — Secure Baseline + SSH Setup (Hostinger)

> **LOCKOUT SAFETY (READ THIS FIRST):**
> - Keep the Hostinger **web console** open while hardening SSH.
> - Keep at least **one root session** open until you confirm your new user can log in with a key.
> - Do **NOT** enable UFW / firewall or disable SSH passwords until key login is confirmed.

## Variables (replace these)
- `YOUR_VPS_IP` = your server IP (example: `85.209.95.66`)
- `ADMIN_USER` = your admin username (example: `ekardeploy`)
- `KEY_NAME` = local SSH key name (example: `ekardeploy`)

---

## 1) Baseline OS checks + updates + base packages (VPS)

### 1.1 Confirm OS + kernel
```bash
cat /etc/os-release
uname -a
```

### 1.2 Update and upgrade packages
```bash
apt update
apt -y full-upgrade
apt -y autoremove --purge
apt -y autoclean
```

### 1.3 Set timezone (optional)
```bash
timedatectl set-timezone America/New_York
timedatectl
systemctl status systemd-timesyncd --no-pager
```

### 1.4 Install baseline packages (grouped)
```bash
apt -y install \
  sudo curl wget ca-certificates gnupg2 lsb-release \
  ufw fail2ban unattended-upgrades apt-listchanges \
  vim-tiny nano less htop iotop iftop \
  iproute2 dnsutils lsof psmisc \
  rsyslog logrotate \
  openssh-server
```

### 1.5 Ensure SSH service is running
```bash
systemctl enable --now ssh
systemctl status ssh --no-pager
```

### 1.6 Baseline: check listening ports
```bash
ss -tulpn
```

---

## 2) Disable LLMNR / mDNS (reduce unnecessary name-resolution exposure)

### 2.1 Backup and edit resolved.conf
```bash
cp -a /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak.$(date +%F_%H%M%S)
nano /etc/systemd/resolved.conf
```

### 2.2 Add/update these values
```ini
[Resolve]
LLMNR=no
MulticastDNS=no
```

### 2.3 Restart and verify
```bash
systemctl restart systemd-resolved
systemctl status systemd-resolved --no-pager
```

---

## 3) Remove Monarx agent (ONLY if installed on your image)

```bash
systemctl stop monarx-agent || true
systemctl disable monarx-agent || true

apt -y purge monarx-agent monarx-protect monarx-protect-autodetect || true
apt -y autoremove --purge
apt -y autoclean

pgrep -a monarx || echo "OK: no monarx processes running"
systemctl status monarx-agent --no-pager || true
ss -tulpn | grep -Ei 'monarx|:1721|:65529' || echo "OK: no monarx ports are listening"

ls -al /etc/apt/sources.list.d/
grep -R "monarx" -n /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || echo "OK: no monarx apt entries found"
rm -f /etc/apt/sources.list.d/monarx.list

apt update
dpkg -l | grep -i monarx || echo "OK: no monarx packages installed"
```

---

## 4) Create user + setup SSH key login (Windows PowerShell + VPS)

### 4.1 Create the admin user and add to sudo (VPS, as root)
Replace `ADMIN_USER` below with your username.
```bash
adduser ADMIN_USER
usermod -aG sudo ADMIN_USER
id ADMIN_USER
```

### 4.2 Generate a NEW SSH key on your laptop (Windows PowerShell)
Run this on your laptop:
```powershell
# Create a dedicated key for this VPS (recommended)
ssh-keygen -t ed25519 -a 64 -f $env:USERPROFILE\.ssh\KEY_NAME -C "ADMIN_USER@hostinger-debian12"
```

Check key files exist:
```powershell
dir $env:USERPROFILE\.ssh
```

Show (copy) the public key:
```powershell
type $env:USERPROFILE\.ssh\KEY_NAME.pub
```

### 4.3 Install the public key on the VPS user (VPS, as root)
```bash
mkdir -p /home/ADMIN_USER/.ssh
chmod 700 /home/ADMIN_USER/.ssh
touch /home/ADMIN_USER/.ssh/authorized_keys
chmod 600 /home/ADMIN_USER/.ssh/authorized_keys
chown -R ADMIN_USER:ADMIN_USER /home/ADMIN_USER/.ssh

nano /home/ADMIN_USER/.ssh/authorized_keys
# Paste the public key line from your laptop, save, exit
```

Re-check permissions (do not skip):
```bash
chown -R ADMIN_USER:ADMIN_USER /home/ADMIN_USER/.ssh
chmod 700 /home/ADMIN_USER/.ssh
chmod 600 /home/ADMIN_USER/.ssh/authorized_keys
```

### 4.4 Laptop: remove old host key record (important after OS reinstall)
```powershell
ssh-keygen -R YOUR_VPS_IP
```

### 4.5 Laptop: test SSH login using the key
```powershell
ssh -i $env:USERPROFILE\.ssh\KEY_NAME -o IdentitiesOnly=yes ADMIN_USER@YOUR_VPS_IP
```

### 4.6 VPS: verify sudo works (run after login as ADMIN_USER)
```bash
sudo whoami
# Expected: root
```

> If the key login test fails, check `/var/log/auth.log` on the VPS:
> ```bash
> tail -n 50 /var/log/auth.log | grep -i sshd
> ```

---

## 5) Harden SSH (key-only, no root SSH, allow only ADMIN_USER)

### 5.1 Backup SSH config (VPS, as root)
```bash
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F_%H%M%S)
```

### 5.2 Create a hardening drop-in (VPS, as root)
This method survives package upgrades and is easier to manage.

```bash
nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Paste:
```conf
# =========================
# SSH Hardening (Debian 12)
# =========================

Protocol 2

# Only allow this user to SSH
AllowUsers ADMIN_USER

# Disable SSH root login
PermitRootLogin no

# Keys only
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

# Keep sessions healthy
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging for investigations
LogLevel VERBOSE
```

### 5.3 Cloud-init warning (VERY IMPORTANT)
Some VPS images include:
- `/etc/ssh/sshd_config.d/50-cloud-init.conf` which may set `PasswordAuthentication yes`

Check:
```bash
grep -Rni 'PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
```

If you see:
- `/etc/ssh/sshd_config.d/50-cloud-init.conf: PasswordAuthentication yes`

**Fix option A (recommended): override cloud-init policy**
```bash
nano /etc/cloud/cloud.cfg.d/99-disable-ssh-passwords.cfg
```

Add:
```yaml
ssh_pwauth: false
```

**Fix option B (direct): edit cloud-init SSH drop-in**
```bash
cp -a /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/50-cloud-init.conf.bak.$(date +%F_%H%M%S)
nano /etc/ssh/sshd_config.d/50-cloud-init.conf
# Change: PasswordAuthentication yes  ->  PasswordAuthentication no
```

### 5.4 Validate SSH config and reload safely
```bash
sshd -t
echo $?   # Expected: 0

systemctl reload ssh
systemctl status ssh --no-pager
```

### 5.5 Confirm the effective SSH config (source of truth)
```bash
sshd -T | egrep -i 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowusers|port'
```

Expected:
- `permitrootlogin no`
- `passwordauthentication no`
- `allowusers ADMIN_USER`

### 5.6 Laptop verification tests (Windows PowerShell)
Keep your root console session open until these pass.

1) Key login still works:
```powershell
ssh -i $env:USERPROFILE\.ssh\KEY_NAME -o IdentitiesOnly=yes ADMIN_USER@YOUR_VPS_IP
```

2) Root login is blocked:
```powershell
ssh root@YOUR_VPS_IP
```

3) Password auth is blocked (should FAIL):
```powershell
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no ADMIN_USER@YOUR_VPS_IP
```

---

## 6) Rollback (if you break SSH)
If you still have console/root access:

```bash
rm -f /etc/ssh/sshd_config.d/99-hardening.conf
sshd -t
systemctl reload ssh
```

Or restore your backup:
```bash
cp -a /etc/ssh/sshd_config.bak.YYYY-MM-DD_HHMMSS /etc/ssh/sshd_config
sshd -t
systemctl reload ssh
```

---

## Next (not included yet)
- UFW firewall rules (allow SSH + 80/443 only)
- Fail2ban jails (sshd + nginx)
- Nginx TLS (Let’s Encrypt) + headers
- Node/Next.js systemd service (non-root)
- Postgres hardening (localhost only, roles, backups)

</details>
