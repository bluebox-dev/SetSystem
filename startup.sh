#!/bin/bash
echo "=================================="
echo "Kickstart bash script for CentOS 7"
echo "by Patcharapong Prohmwichai"
echo "Version 1.1h"
echo "September 11, 2018"
echo "=================================="
# Define script configuration file
KICKSTART_CONFIG="kickstart.yml"

# Condition check
function exec_result() {
	if [ $1 == 0 ]; then
		echo "ok"
	else
		echo "failed"
		exit 1
	fi
}

# Parser YAML File
# Credit: https://gist.github.com/pkuczynski/8665367
function parse_yaml() {
   local prefix=$2
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
      }
   }'
}

# Check root access
## get UID
uid=$(id -u)
## Check for it
[ $uid -ne 0 ] && { echo 'Run this script with root privileges.'; exit 1; } || echo 'Running as root, starting service ... '

# TODO: Check yaml configuration file
echo -n ">> Checking configuration file ... "
ls -al ./$KICKSTART_CONFIG > /dev/null 2>&1
exec_result $?

# TODO: Load yaml configuration file
echo -n ">> Loading configuration file ... "
eval $(parse_yaml $KICKSTART_CONFIG "config_")
exec_result $?

# Set configuration file into variable
LINUX_USERNAME=$config_linux_username
LINUX_PASSWORD=$config_linux_password
LINUX_SSH_PORT=$config_linux_sshport
LINUX_SSH_KEY=$config_linux_sshkey

# Start script and stamp time
echo "============ Starting automation script ============"
StartTime="$(date -u +%s.%N)"

# Install neccessary packages
echo -n ">> Installing neccessary packages ... "
sudo yum install -y ntpdate wget tcpdump gcc perl bind-utils telnet git epel-release net-tools bc > /dev/null 2>&1
# Check and return result
exec_result $?

# Sync date/time
echo -n ">> Synchronizing time to pool.ntp.org server ... "
sudo ntpdate pool.ntp.org > /dev/null 2>&1
# Check and return result
exec_result $?

# Setup auto synchronize date/time every 6 hours
echo -n ">> Adding crontab to auto synchronize date/time ... "
sudo ls -al /var/log/ntpdate-autoupdate.log > /dev/null 2>&1
if [ $? -ne 0 ]; then
	sudo touch /var/log/ntpdate-autoupdate.log
	sudo cat >> /etc/crontab << EOL
### Auto Sync NTP ###
0 */12 * * *	root	/usr/sbin/ntpdate pool.ntp.org >> /var/log/ntpdate-autoupdate.log
EOL
	# Check and return result
	exec_result $?
else
	echo "ok"
fi

# Update system
echo -n ">> Updating system ... "
sudo yum update -y > /dev/null 2>&1
# Check and return result
exec_result $?

# Disable SELinux
echo -n ">> Disable SELinux ... "
sudo sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config > /dev/null 2>&1
# Check and return result
exec_result $?

# Secure SSH service
echo -n ">> Securing ssh service - Change listen port to $LINUX_SSH_PORT ... "
# Secure ssh access
sudo sed -i "s/#Port 22/Port $LINUX_SSH_PORT/g" /etc/ssh/sshd_config > /dev/null 2>&1
# Check and return result
exec_result $?
echo -n ">> Securing SSH Service - Disable permit root login ... "
sudo sed -i "s/#PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config > /dev/null 2>&1
# Check and return result
exec_result $?
echo -n ">> Securing SSH Service - Disable password authentication ... "
sudo sed -i "s/PasswordAuthentication yes/PasswordAuthentication yes/g" /etc/ssh/sshd_config > /dev/null 2>&1
# Check and return result
exec_result $?
echo -n ">> Configure SSH Service - Disable UseDNS to prevent reverse lookup ... "
sudo sed -i "s/#UseDNS yes/UseDNS no/g" /etc/ssh/sshd_config > /dev/null 2>&1
# Check and return result
exec_result $?

# Disable firewalld
echo -n ">> Disable firewalld service ... "
sudo systemctl stop firewalld > /dev/null 2>&1 && sudo systemctl mask firewalld > /dev/null 2>&1
echo "ok"

# Install iptables service
echo -n ">> Install iptables-service package for legacy iptables style ... "
sudo yum install -y iptables-services > /dev/null 2>&1
# Check and return result
exec_result $?

# Initialize iptables rules
echo -n ">> Initializing iptables rules ... "
sudo cat > /etc/sysconfig/iptables << EOL
# Firewall configuration written by patcharp@inet.co.th
# Version 2.0
################
# Filter table #
################
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
###################
# Standard accept #
###################
# Accept ESTABLISHED and RELATED state
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Accept standard ping request 1 packet/ seconds
-A INPUT -p icmp --icmp-type 8 -m length --length 1:920 -m state --state NEW -m limit --limit 1/sec -j ACCEPT
# Accept custom SSH service new connection 10 request / minute
-A INPUT -m state --state NEW -m tcp -p tcp --dport $LINUX_SSH_PORT -m recent --set --name ssh --rsource
-A INPUT -m state --state NEW -m tcp -p tcp --dport $LINUX_SSH_PORT -m recent ! --rcheck --seconds 60 --hitcount 10 --name ssh --rsource -j ACCEPT
# Drop silent
-A INPUT -j DROP
COMMIT
#############
# NAT table #
#############
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
EOL
# Check and return result
exec_result $?

# Enable iptables service
echo -n ">> Enable iptables service ... "
sudo systemctl enable iptables > /dev/null 2>&1
# Check and return result
exec_result $?

# Check existing user
echo -n ">> Checking exsiting user ... "
awk -F':' '{ print $1}' /etc/passwd | grep $LINUX_USERNAME > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "add new user"
	echo -n ">> Adding user ... "
	sudo useradd $LINUX_USERNAME > /dev/null 2>&1
	# Check and return result
	exec_result $?
	echo -n ">> Setup user password ... "
	echo $LINUX_PASSWORD | passwd $LINUX_USERNAME --stdin > /dev/null 2>&1
	# Check and return result
	exec_result $?
else
	echo "do nothing"
fi

# Check existing user
echo -n ">> Checking exsiting admin group ... "
awk -F':' '{ print $1}' /etc/group | grep "^admin$" > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "add new group"
	# Create admin group to access root privileges
	echo -n ">> Creating Admin group ... "
	sudo groupadd admin > /dev/null 2>&1
	# Check and return result
	exec_result $?
else
	echo "do nothing"
fi

# Add new user to admin group
echo -n ">> Add $LINUX_USERNAME to admin group ... "
sudo usermod -aG admin $LINUX_USERNAME > /dev/null 2>&1
# Check and return result
exec_result $?

# Enable admin group to root priviledge
echo -n ">> Enable admin group to access priviledge ... "
sudo cat /etc/sudoers | grep "admin" > /dev/null 2>&1
if [ $? -ne 0 ]; then
	# Allow admin group to root access
	sudo cat >> /etc/sudoers << EOL
# Allow admin group to be root system
%admin	ALL=(ALL)	NOPASSWD: ALL
EOL
	# Check and return result
	exec_result $?
else
	echo "ok"
fi

echo -n ">> Adding user ssh public key ... "
ls -al /home/$LINUX_USERNAME/.ssh > /dev/null 2>&1
if [ $? -ne 0 ]; then
	sudo mkdir /home/$LINUX_USERNAME/.ssh && sudo echo $LINUX_SSH_KEY > /home/$LINUX_USERNAME/.ssh/authorized_keys
	sudo chown -R $LINUX_USERNAME:$LINUX_USERNAME /home/$LINUX_USERNAME/.ssh && sudo chmod -R 0700 /home/$LINUX_USERNAME/.ssh
	# Check and return result
	exec_result $?
else
	# Check authorized_keys file
	ls -al /home/$LINUX_USERNAME/.ssh/authorized_keys > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		# Create new file and echo ssh key file
		sudo echo $LINUX_SSH_KEY > /home/$LINUX_USERNAME/.ssh/authorized_keys
		sudo chown -R $LINUX_USERNAME:$LINUX_USERNAME /home/$LINUX_USERNAME/.ssh && sudo chmod -R 0700 /home/$LINUX_USERNAME/.ssh
	else
	    # Check key existing
		KEY_USERNAME=$(echo $LINUX_SSH_KEY | awk -F' ' '{ print $3}')
	    sudo awk -F' ' '{ print $3}' /home/$LINUX_USERNAME/.ssh/authorized_keys | grep "$KEY_USERNAME" > /dev/null 2>&1
	    if [ $? -ne 0 ]; then
	        # If no mymac air key -> add new else do nothing
	        sudo echo $LINUX_SSH_KEY > /home/$LINUX_USERNAME/.ssh/authorized_keys
	        # Check and return result
	        exec_result $?
	    else
	        echo "do nothing"
	    fi
	fi
fi

# Change location time
echo -n ">> Setup localtime to Asia/Bangkok ... "
sudo cp /usr/share/zoneinfo/Asia/Bangkok /etc/localtime > /dev/null 2>&1
# Check and return result
if [ $? == 0 ]; then
	echo "ok"
else
	echo "do nothing"
fi

# Finished script and stamp time
FinishedTime="$(date -u +%s.%N)"
# Calculate Elapsed time
Elapsed="$(bc <<<"$FinishedTime-$StartTime")"

echo "============ Everything is Success in $Elapsed second(s) : Rebooting system ============"
sleep 5
sudo reboot
