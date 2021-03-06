# RHCSA cheat sheet

## Input Output Redirection
	> overwrite
	< send into command
	>> append 
	<< append into command or file
	2>&1 redirect errors to stdout
	2> redirect errors
	stin = 0 
	stdout =1
	stderr =2

## Use grep and regular expressions to analyze text
	grep "string" file
	egrep '(x|y)'

## Access remote systems using ssh and VNC
	ssh username@remote server
	ssh -X (window passthrough, just like on the bastion)
	vncviewer remote_server
	vino-preferences
	~/.vnc/startup
		required packages are tigervnc ; tigervnc-server ; vino (GNOME)
	scp 
	sftp

## Log in and switch users in multiuser runlevels
	su -
	su
	sudo su -
	sudo -i

## Archive, compress, unpack, and uncompress files using tar, star, gzip, and bzip2
	gzip big.jpg
	bzip2 big.jpg
	gzip -d big.jpg.gz
	bzip2 -d big.jpg.bz2
	tar czvf home.tar.gz /home
	tar xzvf home.tar.gz /home
	yum install star
	star -xattr -H=exustar -c -f=home.star /home/
	star -x -f=home.star

## Create, delete, copy, and move files and directories
	mv -r
	cp
	rm -rf
	touch
	mkdir -p
	rmdir (remove directory only if empty)

## Create hard and soft links
	ln source destination  HARD 
	ln -s source destination SOFT


## List, set, and change standard ugo/rwx permissions

	chmod 777
	chmod g+s
	chmod g+t

## Locate, read, and use system documentation including man, info, and files in /usr/share/doc
	man -k [_selinux |command]
	appropos [command]
	ls /usr/share/doc | grep [command]

# OPERATE RUNNING SYSTEMS
========================
## Identify CPU/memory intensive processes, adjust process priority with renice, and kill processes
	top
	renice
	ps aux | grep [job]
	pgrep -l -u bob
	kill -l
	jobs; kill %1

## Manage System Load
	lscpu
	uptime (1, 5, 15 minutes)

## Locate and interpret system log files
	/var/log/*
	
	systemctl restart rsyslog
	logger -p user.debug "Debug Message Test"
	journalctl

## Start, stop, and check the status of network services using systemctl
	systemctl list-units --type=service
	systemctl status sshd
	systemctl list-unit-files --type=service # all service units
## Start, stop, and check the status of network services
	service x start/stop/restart
	service network start/stop/restart

## List, create, delete, and set partition type for primary, extended, and logical partitions
	fdisk -l
	fdisk /dev/XXX
		*Remember* 4th partition must ALWAYS be extended
		82/83 SWAP/8e LVM

## Create and remove physical volumes, assign physical volumes to volume groups, and create and delete logical Volumes
	parted -s /dev/vdb mkpart primary 1MiB 769MiB
	parted -s /dev/vdb mkpart primary 770MiB 1026MiB
	parted -s /dev/vdb set 1 lvm on
	parted -s /dev/vdb set 2 lvm on
	pvcreate /dev/vdb1 /dev/vb2
	vgcreate VGNAM /dev/vdb1 /dev/vdb2
	vgextend VGNAME PVNAME
	lvcreate -n NAME -l[[extants] [-L 50G] VGNAME
	
	mkfs -t ext4 /dev/vg01/lv01 # add to fstab and mount -a
	systemctl daemon-reload
	
	pvdisplay
	vgdisplay
	lvdisplay
	lvremove
	vgremove
	pvremove

	lvcreate -s -n snapshotlv -L `0G /dev/vgname/lvname <-- create a snamshot
	mount -r ro /dev/vgname/snapshotlv /snapmount <-- if it needs to be mounted

### maintenance on logical volumes
	lvextend LVNAME VGNAME
	xfs_growfs /mnt/point (or -r on lvextend to auto-extend)
	resize2fs /dev/vgname/lvname
	#swap space has to be swapoff'd ; mkswap'd
	; and swapon'd
	
	pvmove /dev/vdb2 #clean out this pv
	vgreduce /dev/vg01
	
## thin pools with stratis
	yum install stratisd stratis-cli # le install
	systemctl enable --now stratisd # le enable
	stratis pool create stratispool1 /dev/vdb # make new pool
	stratis pool list # list pool
	stratis pool add-data stratispool1 /dev/vdc #expand pool
	stratis pool list # verify expanded pool
	stratis blockdev list labpool
	
	stratis filesystem create stratispool1 stratis-filesystem1 # make dis filesystem
	stratis filesystem list # list filesystems
	mkdir /stratisvol # make a mount point
	mount /stratis/stratispool1/stratis-filesystem1 /stratisvol # mount
	stratis filesystem snapshot stratispool1 \stratis-filesystem1 stratis-filesystem1-snap # snapshot
	stratis filesystem list #list the snapshot 
	
	stratis filesystem destroy stratispool1 stratis-filesystem1-snap # clean up

## VDO - Virtual Data Optimizer
	vdo create --name=vdo1 --device=/dev/vdd --vdoLogicalSize=50G
	vdo list
	
	vdo status --name=vdo1 | grep Deduplication
	vdo status --name=vdo1 | grep Compression
	
	mkfs.xfs -K /dev/mapper/vdo1
	udevadm settle
	mkdir /mnt/vdo1
	
	mount /dev/mapper/vdo1 /mnt/vdo1
	vdostats --human-readable
	
## AUTO MOUNT NFS BABY YEAHHH
	yum install autofs
	vim /etc/auto.master.d/demo.autofs
	  # add dis line to dat file: /shares  /etc/auto.demo
	vim /etc/auto.demo # this is where the config magic happens
		# add dis line to dat file: work  -rw,sync  serverb:/shares/work
		# "work" is the mount point under /shares
	sudo systemctl enable --now autofs #starty restarty
	
	# direct maps - in the autofs file:
	/-  /etc/auto.direct
	# in the auto.direct file:
	/mnt/docs  -rw,sync  serverb:/shares/docs
	#magic wildcard maps
	*  -rw,sync  serverb:/shares/&

## edit partitions n stuff
	parted /dev/vdb mklabel newlable
	parted /dev/vdb mkpart primary xfs 2048s 1000MB
	udevadm settle
	mkfs.xfs
	vi /etc/fstab
	systemctl daemon-reload # to reload
	
	findmnt --verify # to verify fstab

## Create, mount, unmount, and use ext2, ext3, and ext4 file systems
	mkfs.ext[2|3|4] /dev/XXXX (for LVM: /dev/mapper/vg-lv)
	mkswap
	swapon
	mount
	umount
	
## Add new partitions and logical volumes, and swap to a system non-destructively
	Unmount the partition or LV to be expanded.
	Add the new PV, extend the vg
		vgextend VG PV
	Extend the unmounted LV
		lvextend -L [AMOUNT]G lv
	Resize
		resize2fs lv
		resize2fs lv specifiedsize : e.g. resize2fs /dev/vg1/lv1 2G
	Remount

## Review mounted filesystems
	lsof /mnt/usb1 #list open files
	lsblk
	lsblk -fp #UUIDs

## Mount, unmount, and use LUKS-encrypted file systems
	cryptsetup luksOpen /dev/xxx newname
	mkdir mydata
	mount /dev/mapper/newname /mydata
	umount etc.

## Extend existing unencrypted ext4-formatted logical volumes
	lvextend
	resize2fs
	
## Create and configure set-GID directories for collaboration
	mkdir
	chown user:group file
	chmod -R 770
	chmod -R g+s
	
	setfacl -m u:user_to_block:000

## verify a package is installed & daemon running
	yum list
	systemctl is-enabled tuned; systemctl is-active tuned
## yum stuff
	yum update
	yum remove PKG
	yum history
	yum list PKG
	yum group list
	yum search WORDS
	yum info PKG
	yum install PKG
	yum group install PKG

# add a repo
	yum-config-manager --add-repo="http://node.dom.com"
	gpgcheck=false
	
## Diagnose and correct file permission problems
	tail /var/log/messages

# network stuff
## network info
	ip link
	ip addr show [interface] # addresses
	ip -s -h link show [interface] #performance
	ping
	ping6
	ip route
	ip -6 route
	tracepath & tracepath6
	ss -ta #(NETSTAT!)
## network command line
	nmcli dev status
	nmcli con show
	nmcli con show "connection name"
	nmcli dev show devname
	vim /etc/sysconfig/network-scripts/ifcfg-name
	nmcli con reload
	nmcli con up "connection name"
	
	getent hosts host.name.com #test dns resolution using hosts file
	host host.name.com #test dns resolution
	
	sudo hostnamectl set-hostname myhost.nydom.com

## Schedule tasks using cron
	man 5 crontab --> this has examples and field information
	*    *    *    *    *  command to be executed
	-    -    -    -    -
	|    |    |    |    |
	|    |    |    |    |
	|    |    |    |    +----- day of week (0 - 6) (Sunday=0)
	|    |    |    +---------- month (1 - 12)
	|    |    +--------------- day of month (1 - 31)
	|    +-------------------- hour (0 - 23)
	+------------------------- min (0 - 59)

## systemd schedule stuff
	Copy /usr/lib/systemd/system/sysstat-collect.timer to /etc/systemd/system/sysstat-collect.timer
	[Timer]
	OnCalendar=*:00/02 # 2019-03-* 12:35,37,39:16
	# OnUnitActiveSec=15min
	
## manage temporary files
	copy /usr/lib/tmpfiles.d/tmp.conf to /etc/tmpfiles.d/tmp.conf
	
# BOOT STUFF
## Configure systems to boot into a specific target automatically
	systemctl set-default graphical.target
	systemctl get-default #to confirm
	
## Select a different target at boot time
	_Append_ systemd.unit=rescue.target to the kernel command line from the boot loader
	(press e to edit  current entry, append this, ctrl+x to boot with those changes)

## Install Red Hat Enterprise Linux automatically using Kickstart
	Boot from media, hit tab, and amend with ks=filelocation 
	e.g. ks=http://instructor.example.com/ks.cfg
	/root/anaconda-ks.cfg
	system-config-kickstart (needs to be installed)

## Reset root password  [ref](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/sec-Terminal_Menu_Editing_During_Boot#proc-Resetting_the_Root_Password_Using_rd.break)
	Reboot, interrupt the boot loader by pressing any key, except enter.

	Move the cursor to the kernel entry to boot (starts with linux)

	'e' to edit the selected entry

	Append rd.break :the system breaks just before the system hands control from the initramfs to the actual system.

	Press Ctrl + x to boot with the changes.
	(The initramfs switch_root prompt appears.)
	mount -o remount,rw /sysroot
	chroot /sysroot
	passwd
	touch /.autorelabel
	exit #chroot	
	exit
	
# troubleshoot boot errors
	vim /etc/systemd/journald.conf # set Storage=persistent
	systemctl restart systemd-journald.service # restart the service
	journalctl -b -1 -p err #show errors since last boot
	
# install stuff
## Configure a system to run a default configuration HTTP server
	yum install httpd
	service httpd start
	chkonfig
	iptables
	iptables -I INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

	iptables-save      ********ALWAYS SAVE YOUR IPTABLES********
	vim /etc/httpd/conf/httpd.conf

## Configure a system to use time services
	timedatectl set-ntp true #enables chronyd
	tzselect
	sudo timedatectl set-timezone America/Port-au-Prince

## Install and update software packages from Red Hat Network, a remote repository, or from the local file system
	yum / rpm
	vim /etc/yum.repos.d/
		[name]
		name=Whatever Name
		baseurl=http://instructor.example.com/repo/
		enabled=1
	(REMEMBER THE TRAILING /)
	
	yum repolist all
	yum-config-manager --enable reponame
	yum-config-manager --add-repo="http://repo.com/repo"
	
## yum modules and streams (RHEL8)
	yum module info modulename:streamnum/profile
	e.g. yum module info derpydoo:10/common

## Modify the system bootloader
	vim /boot/grub/grub.conf

## Create, delete, and modify local user accounts
	useradd
	usermod
	userdel

## Change passwords and adjust password aging for local user accounts
	chage

## Create, delete, and modify local groups and group memberships
	groupadd
	groupdel
	groupmod

Configure a system to use an existing LDAP directory service for user and group information
	system-config-authentication
	dc=example,dc=com

## Configure firewall settings using system-config-firewall or iptables
	/etc/sysconfig/iptables
	iptables -I INPUT -p tcp --dport 22 -j ACCEPT;
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT

## SELinux
### Set enforcing and permissive modes for SELinux
	getenforce
	setenforce 1
	setenforce 0
	vim /etc/sysconfig/selinux

### List and identify SELinux file and process context
	ls -dZ

### Detecting SELinux issues
	less /var/log/messages 
	run the suggested sealert command
	ausearch -m [type|AVC] -ts recent
	
	semanage port -a -t http_port_t -p tcp 8001  # -a add -t type -p port
### Restore default file contexts
        semanage fcontext -a -t '/directory(/.*)?'
	restorecon -Rv /directory
	man -l xx_selinux, eg. httpd_selinux

### Use boolean settings to modify system SELinux settings
	sebool
	getsebool -a | grep whatever
	setsebool -P whateverbool on (DO NOT FORGET THE -P PERSISTENT)


### Diagnose and address routine SELinux policy violations
	Install: setroubleshoot 
	selinux-policy

