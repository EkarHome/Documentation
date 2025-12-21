<details>
<summary>Prepare VPS</summary>
  
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

### Create User and Setup SSH

1. create user.
```bash
adduser ekarops
```

2. add user to sudo group.
```bash
usermod -aG sudo ekarops
```

3. verify user/group.
```bash
id ekarops
```

4. add password and confirm password (interactive prompt during adduser).

5. check if root authorized_keys exists.
```bash
ls -al /root/.ssh/authorized_keys
```

6. if the file exists then do:

7. create ssh folder.
```bash
mkdir -p /home/ekarops/.ssh
```

8. copy authorized_keys from root.
```bash
cp -a /root/.ssh/authorized_keys /home/ekarops/.ssh/authorized_keys
```

9. set ownership.
```bash
chown -R ekarops:ekarops /home/ekarops/.ssh
```

10. set folder permission.
```bash
chmod 700 /home/ekarops/.ssh
```

11. set key permission.
```bash
chmod 600 /home/ekarops/.ssh/authorized_keys
```

12. remove old SSH key from laptop.
```bash
ssh-keygen -R 85.209.95.66
```

13. SSH into server.
```bash
ssh ekarops@85.209.95.66
```
### Harden SSH
```bash
dir $env:USERPROFILE\.ssh #Check if you already have an SSH key
```
```bash
dir $env:USERPROFILE\.ssh #Check if you already have an SSH key
```



### SSH
```bash
whoami #Expected: root
apt update #downloads the latest package list from Debian repositories
systemctl enable --now ssh
systemctl status ssh --no-pager #Check ssh service; Expected: Active (running)
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
```
```bash
#VPS: backup current SSH config
cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F_%H%M%S)
ls -al /etc/ssh/sshd_config*
#VPS: create a hardening drop-in file (recommended method)
nano /etc/ssh/sshd_config.d/99-hardening.conf
PasswordAuthentication no
nano /etc/cloud/cloud.cfg.d/99-disable-ssh-passwords.cfg
ssh_pwauth: false
sshd -t
echo $?
systemctl reload ssh
systemctl status ssh --no-pager
sshd -T | egrep -i 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|allowusers'


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
</details>










<details>
<summary>Old Settings</summary>
  
1. sudo mkdir -p /var/www/ekar
2. apt update && apt upgrade -y
3. apt install -y sudo git build-essential curl nginx unzip
4. sudo timedatectl set-timezone America/New_York
5. curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
6. sudo apt install -y nodejs
7. node -v && npm -v
8. id web 2>/dev/null || adduser --system --group --home /var/www/ekar web
9. chown -R web:web /var/www/ekar
10. sudo -u web rm -rf /var/www/ekar/.next
11. chmod -R u+rwX /var/www/ekar
12. #####copy ekar files to /var/www/ekar
13. sudo -u web -H npm ci
14. sudo -u web -H npm run build
15. copy /etc/systemd/system/ekar.service from the main branch
16. systemctl daemon-reload
17. systemctl enable --now ekar
18. systemctl status ekar --no-pager
19. curl -I http://127.0.0.1:3000
10. copy certs /etc/ssl/certs/ from main branch
11. copy keys /etc/ssl/private/ from main branch
12. chown root:root /etc/ssl/certs/ekarhomeimprovement.crt
13. chown root:root /etc/ssl/private/ekarhomeimprovement.key
14. chmod 644 /etc/ssl/certs/ekarhomeimprovement.crt
15. chmod 600 /etc/ssl/private/ekarhomeimprovement.key
16. copy /etc/nginx/sites-available/ekar from main branch
17. ln -sf /etc/nginx/sites-available/ekar /etc/nginx/sites-enabled/ekar
18. [ -f /etc/nginx/sites-enabled/default ] && rm /etc/nginx/sites-enabled/default
19. apt -y install ufw
20. ufw allow OpenSSH
21. ufw allow "Nginx Full"
22. ufw --force enable
23. ufw status
24. sudo apt install -y postgresql postgresql-contrib
25. ALTER USER postgres WITH PASSWORD 'Rayan1991';
26. ALTER USER web WITH PASSWORD 'Ekar2025';
27. sudo apt install -y certbot python3-certbot-nginx
28. sudo certbot --nginx -d admin.ekarhomeimprovement.com --redirect -m info@ekarhomeimprovement.com --agree-tos -n
29. systemctl status certbot.timer
30. sudo certbot renew --dry-run
31. sudo apt install -y libnginx-mod-http-geoip2 geoipupdate mmdb-bin
32. copy from main branch /etc/GeoIP.conf
33. sudo mkdir -p /usr/share/GeoIP
34. sudo geoipupdate -v
35. ls -lh /usr/share/GeoIP/GeoLite2-City.mmdb
36. mmdblookup --file /usr/share/GeoIP/GeoLite2-City.mmdb --ip 8.8.8.8 country iso_code
37. grep -R "geoip2_module" /etc/nginx/modules-enabled /etc/nginx/nginx.conf || true
38. load_module modules/ngx_http_geoip2_module.so;
39. cd /var/www/ekar
40. node scripts/provision-user.js --email admin@ekarhomeimprovement.com --role superadmin --password "RayanZouheir=2025"
41. sudo journalctl -u ekar.service -e -f
42. node scripts/provision-user.js --email a@b.com --role superadmin --password "ab"
43. psql -U web -d ekar -f database_init/init.sql
</details>
