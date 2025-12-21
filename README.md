### Setting up the VPS
```bash
echo -e "\e[32ms1######\\e[0m" && cat /etc/os-release  && echo -e "\e[31me1######\\e[0m" && echo #prints your OS identification (should show Debian GNU/Linux 12).
echo -e "\e[32ms2######\\e[0m" && uname -a  && echo -e "\e[31me2######\\e[0m"  && echo #prints kernel version + architecture. Useful for troubleshooting and patch verification.
echo -e "\e[32ms3######\\e[0m" && apt update && echo -e "\e[31me3######\\e[0m"  && echo #downloads the latest package index from Debian repos
echo -e "\e[32ms4######\\e[0m" && apt -y full-upgrade && echo -e "\e[31me4######\\e[0m"  && echo #applies all upgrades and handles dependency changes safely.
echo -e "\e[32ms5######\\e[0m" && apt -y autoremove --purge && echo -e "\e[31me5######\\e[0m"  && echo #removes unused dependencies and purges their configs.
echo -e "\e[32ms6######\\e[0m" && apt -y autoclean && echo -e "\e[31me6######\\e[0m"  && echo #removes old downloaded package files.
echo -e "\e[32ms7######\\e[0m" && sudo timedatectl set-timezone America/New_York && echo -e "\e[31me7######\\e[0m"  && echo #set the local time to nyc.
echo -e "\e[32ms8######\\e[0m" && timedatectl && echo -e "\e[31me8######\\e[0m"  && echo #shows system time, timezone, and NTP status.
echo -e "\e[32ms9######\\e[0m" && systemctl status systemd-timesyncd --no-pager && echo -e "\e[31me9######\\e[0m" && echo #shows whether Debian’s time sync service is running.
echo -e "\e[32ms10######\\e[0m" && apt -y install sudo && echo -e "\e[31me10######\\e[0m" && echo #we will stop using root directly (major security step).
echo -e "\e[32ms11######\\e[0m" && apt -y install curl && echo -e "\e[31me11######\\e[0m" && echo #Transfer data to/from URLs (HTTP APIs, downloads).
echo -e "\e[32ms12######\\e[0m" && apt -y install wget && echo -e "\e[31me12######\\e[0m" && echo #Download files from web servers, robust retries.
echo -e "\e[32ms13######\\e[0m" && apt -y install ca-certificates && echo -e "\e[31me13######\\e[0m" && echo #Trusted SSL roots for HTTPS certificate verification.
echo -e "\e[32ms14######\\e[0m" && apt -y install gnupg2 && echo -e "\e[31me14######\\e[0m" && echo #Verify signatures and manage GPG keys.
echo -e "\e[32ms15######\\e[0m" && apt -y install lsb-release && echo -e "\e[31me15######\\e[0m" && echo #Show distro/version info for scripts and support.
echo -e "\e[32ms16######\\e[0m" && apt -y install ufw && echo -e "\e[31me16######\\e[0m" && echo #Simple firewall manager for inbound/outbound rules.
echo -e "\e[32ms17######\\e[0m" && apt -y install fail2ban && echo -e "\e[31me17######\\e[0m" && echo #bans brute-force attempts (SSH, nginx, etc.).
echo -e "\e[32ms18######\\e[0m" && apt -y install unattended-upgrades && echo -e "\e[31me18######\\e[0m" && echo #Automatically install security updates.
echo -e "\e[32ms19######\\e[0m" && apt -y install apt-listchanges && echo -e "\e[31me19######\\e[0m" && echo #Display package changelogs before/after upgrades.
echo -e "\e[32ms20######\\e[0m" && apt -y install vim-tiny && echo -e "\e[31me20######\\e[0m" && echo #Lightweight Vim editor for quick text edits.
echo -e "\e[32ms21######\\e[0m" && apt -y install nano && echo -e "\e[31me21######\\e[0m" && echo #Simple terminal text editor.
echo -e "\e[32ms22######\\e[0m" && apt -y install less && echo -e "\e[31me22######\\e[0m" && echo #Scroll and search through long text output.
echo -e "\e[32ms23######\\e[0m" && apt -y install htop && echo -e "\e[31me23######\\e[0m" && echo #Interactive process viewer and system monitor.
echo -e "\e[32ms24######\\e[0m" && apt -y install iotop && echo -e "\e[31me24######\\e[0m" && echo #Show processes using disk I/O.
echo -e "\e[32ms25######\\e[0m" && apt -y install iftop && echo -e "\e[31me25######\\e[0m" && echo #Show bandwidth usage by network connection.
echo -e "\e[32ms26######\\e[0m" && apt -y install net-tools && echo -e "\e[31me26######\\e[0m" && echo #Legacy networking tools like ifconfig/netstat.
echo -e "\e[32ms27######\\e[0m" && apt -y install iproute2 && echo -e "\e[31me27######\\e[0m" && echo #Modern networking tools: ip, ss, tc.
echo -e "\e[32ms28######\\e[0m" && apt -y install dnsutils && echo -e "\e[31me28######\\e[0m" && echo #DNS tools like dig and nslookup.
echo -e "\e[32ms29######\\e[0m" && apt -y install lsof && echo -e "\e[31me29######\\e[0m" && echo #List open files and listening ports.
echo -e "\e[32ms30######\\e[0m" && apt -y install psmisc && echo -e "\e[31me30######\\e[0m" && echo #Process utilities: killall, pstree, fuser.
echo -e "\e[32ms31######\\e[0m" && apt -y install rsyslog && echo -e "\e[31me31######\\e[0m" && echo #System log daemon for collecting/writing logs.
echo -e "\e[32ms32######\\e[0m" && apt -y install logrotate && echo -e "\e[31me32######\\e[0m" && echo #Rotate/compress logs to prevent disk filling.
echo -e "\e[32ms33######\\e[0m" && apt -y install openssh-server && echo -e "\e[31me33######\\e[0m" && echo #Enable SSH remote login to the server.
echo -e "\e[32ms33.1######\\e[0m" && systemctl enable --now ssh && echo -e "\e[31me33.1######\\e[0m" && echo #Enable SSH remote login to the server.
echo -e "\e[32ms33.2######\\e[0m" && systemctl status ssh --no-pager && echo -e "\e[31me33.2######\\e[0m" && echo #Enable SSH remote login to the server.
echo -e "\e[32ms34######\\e[0m" && ss -tulpn && echo -e "\e[31me34######\\e[0m" && echo #lists all listening TCP/UDP sockets plus the owning process (-p) and numeric ports (-n).
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
