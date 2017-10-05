#!/bin/bash
echo "##################################################"
echo "# Security Script --> by Richard M. (Unfinished) #"
echo "#                                                #"
echo "#             Version : 1.0.5 Beta               #"             
echo "##################################################"
sleep 2 
echo " "
echo "please run this script in ´sudo -i´ mode" 
echo "this script hardens the security of any Linux machine ."
echo "running it can take some time ...."
echo "You may want to edit some thing manually e.g : ssh is on port 222"

### please run this script in "sudo -i" mode
### this script hardens the security of any Linux machine .
### running it can take some time ....
### You may want to edit some things manually e.g : ssh is on port 222
sleep 3

if whoami | grep -q 'root'; 
then 
  echo ""
  echo "Everything OK  --- > you are root :)"
  echo ""
else 
  echo ""
  echo "!!!! Error you are not root !!!!"
  echo ""
  sleep 3
  echo "exiting"
  sleep 2 
exit 1 
fi

#getting ready 

echo ""
echo "###############"
echo "#getting ready#"
echo "###############"
echo ""
sleep 3

#IP 
echo ""
echo "Building encrypted socket to find out your Ip "
echo ""
sleep 3
echo "Please make sure that you are not connected to any VPN / Proxy "
echo ""
IP=$(curl -s https://4.ifcfg.me/)
echo "your ip is $IP"
echo ""
echo "Correct if that is not your real ip"
echo ""
if ( sudo apt-get upgrade | grep -q "0 upgraded, 0 newly installed, 0 to remove" ) ;
then
 
echo "nothing to upgrade :)"

else
 
echo "you have some updates / upgrade to make  to make :/ "
sudo apt-get upgrade 
sudo yum install apt
sudo apt-get update 
sudo apt-get upgrade 
sudo apt-get autoremove 
sudo apt-get autoclean
fi
if sudo apt-get upgrade | grep -q  "0 upgraded, 0 newly installed, 0 to remove";
then 
echo ""
else 
echo "############################################################################"
echo "# !! if you made a major update , mayber you should restart the machine !! #"
echo "#                                                                          #"
echo "#                       Do you want to reboot now ? (Y/N)                  #"
echo "############################################################################"
sleep 3
read bool 

if [[ $bool == *"Y"* ]];
then 
echo ""
echo "rebooting"
sleep 3  
sudo reboot 
elif [[ $bool == *"N"* ]];
then 
echo "Skipping reboot"
sleep 3 
else
echo "!!! Unexpected input : exiting !!!"
sleep 3 
exit 1
fi
fi 
sleep 3
echo ""
echo "#######"
echo "#ready#"
echo "#######"
echo ""
sleep 3 
#beta scripts 

echo ""
echo "#################################################################"
echo "# Do you want to use the secure RSA generator for this machine ?#"
echo "#################################################################"
echo ""
echo "SRG is experimental Y/N ? "
echo
read SRG 
if [[ $SRG == *"Y"* ]]
then 
echo ""
echo "SRG will be used"
else 
echo ""
echo "SRG will not be used ."
fi

#security software 

echo ""
echo "##############################"
echo "#installing security software#"
echo "##############################"
echo ""
sleep 3 
sudo apt-get install ufw 
sudo apt-get install gufw 
sudo apt-get install fail2ban 
sudo apt-get install logwatch 
sudo apt-get install chkrootkit
sudo apt-get install rkhunter 
sudo apt-get install openssl
sudo apt-get install apparmor 
sudo apt-get install nmap 
sudo apt-get install tiger 
sudo apt-get install denyhosts
sudo apt-get install psad
sudo apt-get install gpg
sudo apt-get install secure-delete

###AVG 

if [ -f ~/avg2013flx-r3115-a6155.i386.deb ]
then 
echo ""
echo "##############################################################"
echo "#You alreday donloaded the avg package --> no need to install#"
echo "##############################################################"
echo ""
sleep 3
else 

wget http://download.avgfree.com/filedir/inst/avg2013flx-r3115-a6155.i386.deb
avgchks="0eca39d7d6253e89c870e6f6c4b50e42f0c970007237c82ac0706bf4ad1c96fba24802068c691daecca49a87b71851d88dae850d8901b4163f43c2c8c412eee3"
if sha512sum avg2013flx-r3115-a6155.i386.deb | grep -q "$avgchksum" 
then 
echo ""
echo "the checksum of your compressed AVG installation seems good ."
echo ""
echo "sha512 checksum : 0eca39d7d6253e89c870e6f6c4b50e42f0c970007237c82ac0706bf4ad1c96fba24802068c691daecca49a87b71851d88dae850d8901b4163f43c2c8c412eee3 "
echo ""
else 
echo "Your AVG .deb got tampered with ! removing "
sudo rm avg2013flx-r3115-a6155.i386.deb
fi
fi 
if sudo avgscan | grep -q "AVG command line Anti-Virus scanner"
then
echo "You already have AVG installation is fine "
echo "No need to install"
else 
sudo apt-get install ia32-libs
sudo dpkg -i avg2013flx-r3115-a6155.i386.deb
if avgupdate | grep -q "Copyright (c) 2013 AVG Technologies CZ";
then 
echo "Your Avg-AV Installation seems alright :)"
else 
echo "Your Avg-AV Installation seems broken :("
sleep 3 
echo "This is a common error and a solution is in progress "
echo "for now it is safer to uninstall the build ..."
sudo apt-get remove --purge avg2013flx 
echo "done "
sleep 2
fi
fi

echo ""
echo "###########################################"
echo "#successfully installed security software#"
echo "###########################################"
echo ""
sleep 3 

#encrypt 

echo ""
echo "#########################################################"
echo "# Do you want to en- / decrypt files or folders ? (Y/N) #"
echo "#########################################################"
echo ""
read encryptyn
if [[ $encryptyn == *"Y"* ]]
then 
if [ -d /etc/VSHG ]
then 
echo "##########################"
echo "# VSHG already installed #"
echo "##########################"
echo ""
cd /etc/VSHG
else 
sudo rm -R /etc/VSHG
git clone https://github.com/RichardRMatthews/VSHG.git /etc/VSHG
cd /etc/VSHG
sudo chmod +x VSHG_1.4.sh
fi 
while [[ $encryptyn == *"Y"* ]]
do
./VSHG_1.4.sh
echo ""
echo "Do you want to de- /encrypt more files / folders (Y/N)"
read encryptyn
done
else 
echo "skipping encryption ! "
fi 

#servers

echo ""
echo  "####################"
echo  "#installing servers#"
echo  "####################"
echo ""
sleep 3
sudo apt-get install vsftpd 
sudo apt-get install openssh-server 
sudo apt-get install apache2 
sudo apt-get install apache2-utils 
sleep 2
echo "done"
echo ""
echo "Checking Servers..."
sudo service vsftpd restart
if sudo service vsftpd status | grep -q "active (running)"
then 
echo ""
echo "vsftpd looks fine ."
echo ""
else 
echo ""
echo " !!! vsftpd has got a problem , attemting reinstall and removing .conf !!!"
echo ""
sudo apt-get remove --purge vsftpd 
sudo apt-get install vsftpd
fi 
sudo service apache2 restart
if sudo service apache2 status | grep -q "active (running)"
then 
echo ""
echo "apache looks fine ."
echo ""
else 
echo ""
echo " !!! apache has got a problem , attemting reinstall and removing .conf !!!"
echo ""
sudo apt-get remove --purge apache2  
sudo apt-get install apache2
fi 
sudo service ssh restart
if sudo service ssh status | grep -q "active (running)"
then 
echo ""
echo "ssh looks fine ."
echo ""
else 
echo ""
echo " !!! ssh has got a problem , attemting reinstall and removing .conf !!!"
echo ""
sudo apt-get remove --purge openssh-server 
sudo apt-get install openssh-server
fi 


#security Enable-ing

echo ""
echo "#############################"
echo "#enabeling security software#"
echo "#############################"
echo ""
sleep 3
sudo update-rc.d ufw enable
sudo ufw allow 22
sudo ufw allow 21 
sudo ufw allow 222
sudo ufw allow 10100
sudo update-rc.d fail2ban enable 
sudo update-rc.d vsftpd enable 
sudo update-rc.d sshd enable
sudo update-rc.d ssh enable 
echo ""
echo "#########################################"
echo "#successfully enabeld security software#"
echo "#########################################"
echo ""
sleep 3

#security settings 


###Anti Ip spoofing 

echo ""
echo "######################################"
echo "#Disabeling Ip-Spoofing vulnerability#"
echo "######################################"
echo ""
sleep 3 
sudo rm /etc/host.conf
sudo echo 'multi on 
 order bind,hosts
 nospoof on' >> /etc/host.conf

echo ""
echo "##################################"
echo "#successfully fixed Ip - Spoofing#"
echo "##################################"
echo ""
sleep 3

###SSL enhancing 

echo ""
echo "#################"
echo "# Enhancing SSL #"
echo "#################"
echo ""
sleep 3 
echo "Deleting old ssl files "
echo ""
sudo srm /etc/ssl/private/ssl-cert-snakeoil.key
sudo srm /etc/ssl/certs/ssl-cert-snakeoil.pem
if [[ $SRG == *"Y"* ]]
then 
echo ""
echo "Using SRG "
sleep 2
#Secure RSA generator 
#SRG
echo "#####################################"
echo "# SRG by ----> Richard R. Matthews  #"
echo "#####################################"
sleep 3 
if whoami | grep -q "root"
then 
echo ""
echo "you are root --> Everything ok "
else 
echo ""
echo "you should be root "
echo ""
sleep 2 
exit 1 
fi 
Random=$( wget -q https://www.random.org/cgi-bin/randbytenbytes=128&format=o  );
if wget -q https://www.random.org/cgi-bin/randbyte?nbytes=128&format=o | grep -q "You have used your quota of random bits for today. See the quota page for details.";
then 
sudo service tor restart
proxychains wget -q https://www.random.org/cgi-bin/randbyte?nbytes=128&format=o 
echo ""
fi
echo ""
echo "got entropy"
echo ""
if [ -f /root/randbyte?nbytes=128 ]
then 
echo "Successfully gathered entropy containing file "
sudo openssl req -x509 -rand /root/randbyte?nbytes=128 -batch -nodes -newkey RSA:4096 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem
else 
echo "Failed ! No Random file gathered . "
fi
sleep 3
if [ -f /etc/ssl/private/ssl-cert-snakeoil.key ]
then 
echo ""
echo "successfully generated true random RSA keys"
sleep 3 
else 
echo "!!! Failed to generate key !!! "
echo ""
echo "since the key generation failed running emergancy key generation  "
sudo openssl req -x509 -nodes -batch -newkey RSA:2048 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem
sleep 3 
fi 
echo ""
echo "shreddering the enropy containing file ..."
echo ""
sleep 3 
sudo srm /root/randbyte?nbytes=128
sleep 3 
echo "Successfully shredderd "
echo ""
echo "################"
echo "# SRG finished #"
echo "################"

sleep 2
else 
sudo openssl req -x509 -nodes -newkey RSA:2048 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem
fi
echo ""
echo "############################"
echo "#Seccessfully enhanced SSL #"
echo "############################"
echo ""
sleep 3 

###DNS Binding 

echo ""
echo "######################"
echo "#Binding DNS service #"
echo "######################"
echo ""
sleep 3
sudo rm /etc/bind/named.conf.options
sudo echo 'recursion no;
version "Not Disclosed";' >> /etc/bind/named.conf.options
sudo service bind9 restart
echo ""
echo "################################"
echo "#successfully bound DNS service#"
echo "################################"
echo ""
sleep 3

###PHP Hardening 

echo ""
echo "###############"
echo "#PHP Hardening#"
echo "###############"
echo ""
sleep 3 
echo ' disable_functions = exec,system,shell_exec,passthru
register_globals = Off
expose_php = Off
display_errors = Off
track_errors = Off
html_errors = Off
magic_quotes_gpc = Off
mail.add_x_header = Off
session.name = NEWSESSID ' >> /etc/php5/apache2/php.ini
sudo service apache2 restart
echo ""
echo "###########################"
echo "#Successfully hardened PHP#"
echo "###########################"
echo ""
sleep 3 


###Securing SSH server 

echo ""
echo "##########################"
echo "#Securing OpenSSH-Server #"
echo "##########################"
echo ""
sleep 3

sudo service sshd stop 

sudo srm /etc/ssh/ssh_host*
sudo dpkg-reconfigure openssh-server 
sudo rm /etc/ssh/sshd_config 
sudo echo '

Port 222
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::
#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key
#RekeyLimit default none
#SyslogFacility AUTH
#LogLevel INFO
#LoginGraceTime 2m
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5
#PubkeyAuthentication yes
#AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2
#AuthorizedPrincipalsFile none
#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody
#HostbasedAuthentication no
#IgnoreUserKnownHosts no
#IgnoreRhosts yes
PasswordAuthentication yes
#PermitEmptyPasswords no
ChallengeResponseAuthentication no
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
UsePAM yes
#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
#UsePrivilegeSeparation sandbox
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none
#Banner none
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
' >> /etc/ssh/sshd_config 

sudo service ssh restart 
sudo service sshd start 

echo ""
echo "######################################"
echo "#succsessfully Secured OpenSSH-Server#"
echo "######################################"
echo ""
sleep 3
echo "!!! SSH Port Will be 222 !!!"
echo ""
sleep 5

###Securing FTP server 

echo ""
echo "################################"
echo "#Securing vsftpd FTP - Server  #"
echo "################################"
echo ""
sleep 3

sudo service vsftpd stop
sudo rm /etc/vsftpd.conf 
echo ""
echo "Generating ssl for vsftpd "
echo ""

if [[ $SRG == *"Y"* ]]
then 
echo ""
echo "Using SRG "
sleep 2
#Secure RSA generator ( vsftpd ) 
#SRG
echo "####################################"
echo "# SRG by ----> Richar R. Matthews  #"
echo "####################################"
sleep 3 
if whoami | grep -q "root"
then 
echo ""
echo "you are root --> Everything ok "
else 
echo ""
echo "you should be root "
echo ""
sleep 2 
exit 1 
fi 
Random=$( wget -q https://www.random.org/cgi-bin/randbytenbytes=128&format=o  );
if wget -q https://www.random.org/cgi-bin/randbyte?nbytes=128&format=o | grep -q "You have used your quota of random bits for today. See the quota page for details.";
then 
sudo service tor restart
proxychains wget -q https://www.random.org/cgi-bin/randbyte?nbytes=128&format=o 
echo ""
fi
echo ""
echo "got entropy"
echo ""
if [ -f /root/randbyte?nbytes=128 ]
then 
echo "Successfully gathered entropy containing file "
sudo openssl req -x509 -rand /root/randbyte?nbytes=128 -batch -nodes -newkey RSA:2048 -keyout /etc/ssl/private/universal.key -out /etc/ssl/certs/universal.crt
else 
echo "Failed ! No Random file gathered . "
fi
sleep 3
if [ -f /etc/ssl/private/universal.key ]
then 
echo ""
echo "successfully generated true random RSA keys"
sleep 3 
else 
echo "!!! Failed to generate key !!! "
echo ""
echo "since the key generation failed running emergancy key generation  "
sudo openssl req -x509 -nodes -batch -newkey RSA:2048 -keyout /etc/ssl/private/universal.key -out /etc/ssl/certs/universal.crt
sleep 3 
fi 
echo ""
echo "shreddering the enropy containing file ..."
echo ""
sleep 3 
sudo srm /root/randbyte?nbytes=128
sleep 3 
echo "Successfully shredderd "
echo ""
echo "################"
echo "# SRG finished #"
echo "################"
sleep 2
else 
sudo openssl req -x509 -nodes -newkey RSA:2048 -keyout /etc/ssl/private/universal.key -out /etc/ssl/certs/universal.crt
fi

sudo echo '
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
#local_umask=022
anon_upload_enable=NO
anon_mkdir_write_enable=NO
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
#chown_uploads=YES
#chown_username=whoever
#xferlog_file=/var/log/vsftpd.log
#xferlog_std_format=YES
#idle_session_timeout=600
#data_connection_timeout=120
#nopriv_user=ftpsecure
#async_abor_enable=YES
#ascii_upload_enable=YES
#ascii_download_enable=YES
ftpd_banner=Keep Out !
#deny_email_enable=YES
#banned_email_file=/etc/vsftpd.banned_emails
#chroot_local_user=YES
#chroot_local_user=YES
#chroot_list_enable=YES 
#chroot_list_file=/etc/vsftpd.chroot_list
#ls_recurse_enable=YES
secure_chroot_dir=/
rsa_cert_file=/etc/ssl/certs/universal.crt
rsa_private_key_file=/etc/ssl/private/universal.key
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
ssl_ciphers=HIGH
local_root=/
pasv_enable=YES
pasv_max_port=10100
pasv_min_port=10100
' >> /etc/vsftpd.conf 
echo "pasv_address=$IP" >> /etc/vsftpd.conf 

sudo service vsftpd start

echo ""
echo "##################################"
echo "#succsessfully Secured FTP Server#"
echo "##################################"
echo ""
sleep 3 
echo "!!! note that you have to add your exteran address to --> pasv_address= and have to forward port 10100 !!!"
sleep 3

###Securing apache2 

echo ""
echo "#############################"
echo "#Securing apache Info - Leak#"
echo "#############################"
echo ""
sudo service apache2 stop
sleep 3 
echo " ServerTokens Prod
ServerSignature Off
TraceEnable Off
Header unset ETag
Header always unset X-Powered-By
FileETag None
" > /etc/apache2/conf-available/security.conf
sudo service apache2 restart
echo ""
echo "#########################################"
echo "#Successfully Secured apache Info - Leak#"
echo "#########################################"
echo ""
sleep 3 

###Securing Apache SSL

echo ""
echo "#####################"
echo "#Securing apache SSL#"
echo "#####################"
echo ""
sudo service apache2 stop
sleep 3 
echo "<IfModule mod_ssl.c>
        SSLRandomSeed startup builtin
        SSLRandomSeed startup file:/dev/urandom 512
        SSLRandomSeed connect builtin
        SSLRandomSeed connect file:/dev/urandom 512
        AddType application/x-x509-ca-cert .crt
        AddType application/x-pkcs7-crl .crl
        SSLPassPhraseDialog  exec:/usr/share/apache2/ask-for-passphrase
        #SSLSessionCache                 dbm:${APACHE_RUN_DIR}/ssl_scache
        SSLSessionCache         shmcb:${APACHE_RUN_DIR}/ssl_scache(512000)
        SSLSessionCacheTimeout  300
        #Mutex file:${APACHE_LOCK_DIR}/ssl_mutex ssl-cache
        SSLCipherSuite HIGH:!aNULL
        #SSLHonorCipherOrder on
        SSLProtocol all -SSLv2 -SSLv3
        #SSLInsecureRenegotiation on
        #SSLStrictSNIVHostCheck On
</IfModule>
" > /etc/apache2/mods-available/ssl.conf
sudo service apache2 restart
echo ""
echo "#################################"
echo "#Successfully secured apache SSL#"
echo "#################################"
echo ""
sleep 3 

###Configuring Fail2ban 

echo ""
echo "#################################"
echo "#Configuring Fail2ban auth jails#"
echo "#################################"
echo ""
sleep 3

sudo rm /etc/fail2ban/jail.conf 
sudo echo ' [DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 1200
findtime = 120
maxretry = 3
backend = auto
usedns = warn
destemail = 
sendername = Fail2Ban
banaction = iptables-multiport
mta = sendmail
protocol = tcp
chain = INPUT
action_ = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protoco$
action_mw = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(proto$
              %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="$
action_mwl = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(prot$
               %(mta)s-whois-lines[name=%(__name__)s, dest="%(destemail)s", log$
action = %(action_mwl)s

[ssh]

enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3

[dropbear]

enabled  = true 
port     = ssh
filter   = dropbear
logpath  = /var/log/auth.log
maxretry = 3

[pam-generic]

enabled  = true 
filter   = pam-generic
port     = all
banaction = iptables-allports
port     = anyport
logpath  = /var/log/auth.log
maxretry = 3

[xinetd-fail]

enabled  sudo vi /etc/fstab = true
filter    = xinetd-fail
port      = all
banaction = iptables-multiport-log
logpath   = /var/log/daemon.log
maxretry  = 2
[ssh-ddos]

enabled  = true
port     = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 3

enabled = ture 
filter = sshd
action = route
logpath = /var/log/sshd.log
maxretry = 3

[ssh-iptables-ipset4]

enabled  = ture 
port     = ssh
filter   = sshd
banaction = iptables-ipset-proto4
logpath  = /var/log/sshd.log
maxretry = 3

[ssh-iptables-ipset6]

enabled  = ture 
port     = ssh
filter   = sshd
banaction = iptables-ipset-proto6
logpath  = /var/log/sshd.log
maxretry = 3

[apache]

enabled  = ture 
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache*/*error.log
maxretry = 3

[apache-noscript]

enabled  = true 
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache*/*error.log
maxretry = 3

[apache-overflows]

enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache*/*error.log
maxretry = 2

[apache-modsecurity]

enabled  = true 
filter   = apache-modsecurity
port     = http,https
logpath  = /var/log/apache*/*error.log
maxretry = 2

[apache-nohome]

enabled  = true 
filter   = apache-nohome
port     = http,https
logpath  = /var/log/apache*/*error.log
maxretry = 2

[php-url-fopen]

enabled = true 
port    = http,https
filter  = php-url-fopen
logpath = /var/www/*/logs/access_log

[lighttpd-fastcgi]

enabled = true 
port    = http,https
filter  = lighttpd-fastcgi
logpath = /var/log/lighttpd/error.log

[lighttpd-auth]

enabled = true
port    = http,https
filter  = suhosin
logpath = /var/log/lighttpd/error.log

[nginx-http-auth]

enabled = true
filter  = nginx-http-auth
port    = http,https
logpath = /var/log/nginx/error.log

[roundcube-auth]

enabled  = true 
filter   = roundcube-auth
port     = http,https
logpath  = /var/log/roundcube/userlogins


[sogo-auth]

enabled  = true 
filter   = sogo-auth
port     = http, https
# without proxy this would be:
# port    = 20000
logpath  = /var/log/sogo/sogo.log

[proftpd]

enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = proftpd
logpath  = /var/log/proftpd/proftpd.log
maxretry = 3


[pure-ftpd]

enabled  = true 
port     = ftp,ftp-data,ftps,ftps-data
filter   = pure-ftpd
logpath  = /var/log/syslog
maxretry = 3


[wuftpd]

enabled  = true 
port     = ftp,ftp-data,ftps,ftps-data
filter   = wuftpd
logpath  = /var/log/syslog
maxretry = 3

[vsftpd]

enabled  = true 
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 3

[postfix]

enabled  = true 
port     = smtp,ssmtp,submission
filter   = postfix
logpath  = /var/log/mail.log


[couriersmtp]

enabled  = true 
port     = smtp,ssmtp,submission
filter   = couriersmtp
logpath  = /var/log/mail.log


[courierauth]

enabled  = true 
port     = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter   = courierlogin
logpath  = /var/log/mail.log

[sasl]

enabled  = true 
port     = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter   = postfix-sasl
logpath  = /var/log/mail.log

[dovecot]

enabled = true
port    = smtp,ssmtp,submission,imap2,imap3,imaps,pop3,pop3s
filter  = dovecot
logpath = /var/log/mail.log

[mysqld-auth]

enabled  = true 
filter   = mysqld-auth
port     = 3306
logpath  = /var/log/mysqld.log

#[named-refused-udp]
#
#enabled  = false
#port     = domain,953
#protocol = udp
#filter   = named-refused
#logpath  = /var/log/named/security.log

[named-refused-tcp]

enabled  = true 
port     = domain,953
protocol = tcp
filter   = named-refused
logpath  = /var/log/named/security.log

[freeswitch]

enabled  = true 
filter   = freeswitch
logpath  = /var/log/freeswitch.log
maxretry = 10
action   = iptables-multiport[name=freeswitch-tcp, port="5060,5061,5080,5081", protocol=tcp]
           iptables-multiport[name=freeswitch-udp, port="5060,5061,5080,5081", protocol=udp]

[ejabberd-auth]

enabled  = true 
filter   = ejabberd-auth
port     = xmpp-client
protocol = tcp
logpath  = /var/log/ejabberd/ejabberd.log

[asterisk-tcp]

enabled  = true 
filter   = asterisk
port     = 5060,5061
protocol = tcp
logpath  = /var/log/asterisk/messages

[asterisk-udp]

enabled  = true 
filter   = asterisk
port     = 5060,5061
protocol = udp
logpath  = /var/log/asterisk/messages

[recidive]

enabled  = true 
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = iptables-allports[name=recidive]
           sendmail-whois-lines[name=recidive, logpath=/var/log/fail2ban.log]
bantime  = 604800  ; 1 week
findtime = 86400   ; 1 day
maxretry = 5

[ssh-blocklist]

enabled  = true 
filter   = sshd
action   = iptables[name=SSH, port=ssh, protocol=tcp]
           sendmail-whois[name=SSH, dest="%(destemail)s", sender="%(sender)s", sendername="%(sendername)s"]
           blocklist_de[email="%(sender)s", apikey="xxxxxx", service="%(filter)s"]
logpath  = /var/log/sshd.log
maxretry = 10

[nagios]
enabled  = true 
filter   = nagios
action   = iptables[name=Nagios, port=5666, protocol=tcp]
           sendmail-whois[name=Nagios, dest="%(destemail)s", sender="%(sender)s", sendername="%(sendername)s"]
logpath  = /var/log/messages     ; nrpe.cfg may define a different log_facility
maxretry = 1


' >> /etc/fail2ban/jail.conf
sudo service fail2ban restart 
echo ""
echo "##########################################"
echo "#finished Configuring Fail2ban auth jails#"
echo "##########################################"
echo ""
sleep 3



###Harden Network 

echo ""
echo "####################"
echo "#Hardening Network #"
echo "####################"
echo ""
sleep 3

sudo rm /etc/sysctl.conf

echo '# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.conf

echo '
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.conf

echo '
# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0' >> /etc/sysctl.conf

echo '
# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.conf

echo '
# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5 ' >> /etc/sysctl.conf

echo '
# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore
_bogus_error_responses = 1 ' >> /etc/sysctl.conf

echo '
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0 ' >> /etc/sysctl.conf

echo '
# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1 ' >> /etc/sysctl.conf 

echo ""
echo "###############################"
echo "#Successfully hardened Network#"
echo "###############################"
echo ""
sleep 3


###Securing shared memory 

echo ""
echo "########################"
echo "#Securing shared memory#"
echo "########################"
echo ""
sleep 3

sudo echo ' tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0 ' >> /etc/fstab

echo ""
echo "####################################"
echo "#Successfully secured shared memory#"
echo "####################################"
echo ""
sleep 3

#security check         
                                  
echo "####################################"
echo "# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#"
echo "#      Congrats all is set !       #"
echo "# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#"
echo "####################################"
sleep 3 
echo ""
echo "#####################################################################################"
echo "# To ensure the security of your System you should perform the final security check #"
echo "#                                                                                   #"
echo "# Do you want to Perform the security check now ? ( That can take a while ...)      #"
echo "#####################################################################################"
echo ""
echo "Y/N : "
read seccheck
if [[ $seccheck == *"Y"* ]];
then 
echo ""
echo "#################################"
echo "#Performing final security check#"
echo "#################################"
echo ""
sleep 3

sudo nmap localhost -sS -sV || bash 
sudo rm ~/avg2013flx-r3115-a6155.i386.deb
sudo ufw status
sudo logwatch  
sudo apt-get update 
sudo apt-get upgrade
sudo apt-get autoremove 
sudo apt-get autoclean
sudo rkhunter --check
sudo chkrootkit
sudo avgupdate 
sudo avgscan -H -c -k -P /
sudo tiger
else 
echo "Ok no security check then :( "
echo ""
sleep 3 
exit 1 
fi 
echo ""
echo "Thank you for using my script"
