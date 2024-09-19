#!/bin/bash

###
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

#=========================================================================================================
# Program: install_sms2_rocky_linux_8.sh
#
# Ver         Date            Author          Comment    
# =======     ===========     ===========     ==========================================
# V1.0.00     2023-01-30      DW              Install SMS 2.0 on Rocky Linux 8.x by using Nginx as web server, 
#                                             and RabbitMQ as queue server.
# V1.0.01     2023-05-18      DW              Add OpenVZ platform checking to decide different installation 
#                                             action, due to OpenVZ doesn't support snap.
# V1.0.02     2023-10-10      DW              Add two more NPM libraries 'arraybuffer-encoding' and 
#                                             'hash-wasm'. Force upgrade NPM library 'qs' to version 6.5.3 or 
#                                             above to patch a security hole.     
# V1.0.03     2024-02-16      DW              Remove NPM library crypto-js.js installation. 
# V1.0.04     2024-02-27      DW              Create a key used to the DH exchange of Nginx.
# V1.0.05     2024-03-24      DW              Add NPM package 'crystals-kyber-js'.
# V1.0.06     2024-04-13      DW              Make a daily task to enable all stable feature flags for 
#                                             RabbitMQ broker.
# V1.0.07     2024-04-21      DW              Use Node.js 20.x on SMS 2.0 installation.
# V1.0.08     2024-09-18      DW              Replace NPM package 'crystals-kyber-js' by 'mlkem'.
#=========================================================================================================

setterm -blank 0

clear

#-- Check whether current user is super user --#
if [[ $EUID > 0 ]]
then
  echo "You must run me by super user, and apparently it is not you!"
  echo ""
  exit 1
fi

#-- Define variables --#
export BUILD_PRELOAD=N
export PATH=$PATH:/usr/local/bin:/usr/sbin:/usr/local/sbin:

#-- Check currently running operating system and it's version --#
v1=`hostnamectl | grep "Rocky Linux 8" | wc -l`
if [[ "$v1" -eq 0 ]] 
then
  echo "Currently running" `hostnamectl | grep "Operating System"`
  echo ""
  echo "SMS 2.0 is not specified for your Linux distro, inatallation on it is likely to fail."
  echo ""
  read -p "Do you want to continue (Y/N)? " TOGO
  if (test ${TOGO} = 'y' || test ${TOGO} = 'Y')
  then
    echo ""
    echo "OK, it is your call, let's go on."
    echo ""
  else
    exit 1
  fi
fi

#-- Check whether SMS 2.0 has already been installed. If it is, stop proceed. --#
if [ -d "/www/sms2" ] 
then
  echo "It seems that SMS 2.0 has been installed (at least it has been tried to be installed before). Therefore, sub-directory 'sms2' "
  echo "has already existed on directory '/www'."
  echo ""
  echo "If SMS 2.0 installation is failure and you need to try again, you have to delete this sub-directory on '/www'"
  echo "manually and re-run installation script 'install_sms2.sh'."
  echo ""
  echo "Note: Re-run installation script in a production SMS 2.0 server will damage everything on it."
  echo ""
  read -p "Press enter to exit..."
  exit 1
fi

#-- Check whether SELinux is enforced. If it is, disable it and reboot the server before installation. --#
#-- Note: SELinux makes many normal operations of SMS 2.0 failure during installation and operation.   --#
x=`cat /etc/selinux/config | grep "SELINUX=enforcing" | wc -l`
if (($x > 0))
then
  echo "It seems that the server setting is needed to be modified for SMS installation"
  read -p "Press enter to modify system setting..."

  if [ ! -f "/etc/selinux/config.sms2bkup" ]
  then  
    cp -f /etc/selinux/config /etc/selinux/config.sms2bkup
  fi  
  cp -f ./sys/config /etc/selinux/config
  echo ""
  echo "It is done. You need to reboot the server and run the installation program again."
  read -p "Press enter to reboot the server..."
  shutdown -r now
fi  

#-- Ensure the enterprise packages repository installed --#
er=`dnf list installed epel-release | grep epel-release | wc -l`
if [[ "$er" -eq 0 ]]
then 
  echo "Install enterprise packages repository"
  dnf -y install epel-release >> /tmp/install.log
else  
  echo "Refresh software repository, please wait..."
  dnf -y upgrade >> /tmp/install.log
fi

whatos=`systemd-detect-virt`
if [ "$whatos" != "openvz" ]
then
  #-- If snapd doesn't exist, install it now and reboot the system. --#
  sn=`dnf list installed snapd | grep snapd | wc -l`
  if [[ "$sn" -eq 0 ]]
  then
    echo "Install snapd, please wait..."
    dnf -y install snapd >> /tmp/install.log
    systemctl enable --now snapd.socket >> /tmp/install.log
    systemctl start snapd.socket >> /tmp/install.log
    systemctl enable --now snap.seeded.service >> /tmp/install.log
    systemctl start snap.seeded.service >> /tmp/install.log
    ln -s /var/lib/snapd/snap /snap
    echo ""
    echo "Since snapd has just been installed, you need to reboot the server and run the installation program again."
    read -p "Press enter to reboot the server..."
    shutdown -r now  
  fi
fi  

#-- Start installation process --#
clear
echo "Before you start the SMS 2.0 installation, you must fulfil the following requirements:"
echo ""
echo "1. You must be administrative user. (i.e. You are 'root' or 'root' equivalent user)"
echo "2. You need a fast enough internet connection during installation. (> 3 Mb/s)"
echo "3. You have registered a domain name for the SMS server site, and it has already been pointed to this server's public IP address."
echo "4. You have an email address for the SMS administrator. (Note: 1. It should not link to your true identity, 2. It is optional.)"
echo "5. You have at least one more email account for SMS routine operations. (Note: It is optional)"
echo ""
echo "Note: If you have no email accounts required, you must input 1 for connection mode on step 5."
echo ""
read -p "If you don't fulfil the above requirements, please press CTRL-C to abort. Otherwise, you may press enter to start the installation..."

echo ""
echo "======================================================================================================"
echo "Step 1: Install required utilities and packages"
echo "======================================================================================================"
echo "Refresh packages"
dnf -y update > /tmp/install.log
echo "Install and configure internet time utilities"
dnf -y install chrony >> /tmp/install.log
systemctl enable chronyd >> /tmp/install.log
systemctl start chronyd >> /tmp/install.log
hwclock -w
#-- Default time zone is UTC, and I set time zone to Hong Kong (UTC+8). Please change it to your desired time --# 
#-- zone. See this URL for more details: https://wiki.crowncloud.net/?How_To_Change_Timezone_on_CentOS_8      --#                                                                 
timedatectl set-timezone Asia/Hong_Kong
#-- If firewall is not installed, install and configure it now. Otherwise, just configure it. --#
whatos=`systemd-detect-virt`
if [ "$whatos" != "openvz" ]
then
  fw=`dnf list installed firewalld | grep firewalld | wc -l`
  if [[ "$fw" -eq 0 ]]
  then
    echo "Install firewall"
    dnf -y install firewalld >> /tmp/install.log
  fi
  systemctl enable firewalld >> /tmp/install.log
  systemctl restart firewalld >> /tmp/install.log
  checker=`systemctl status firewalld | grep "Active: active (running)" | wc -l`
  if [[ "$checker" -eq 0 ]] 
  then
    echo "Unable to start the firewall, error details please refer to the log file /tmp/install.log"
    exit 1;
  fi
  echo "Configure firewall"  
  firewall-cmd --zone=public --permanent --add-service=ssh
  firewall-cmd --zone=public --permanent --add-service=http
  firewall-cmd --zone=public --permanent --add-service=https
  firewall-cmd --zone=public --permanent --add-port=8443/tcp
  firewall-cmd --zone=public --permanent --add-icmp-block=echo-request
  firewall-cmd --reload
else
  #-- For OpenVZ host, only UFW Firewall is working. --#
  fw=`dnf list installed ufw | grep ufw | wc -l`
  if [[ "$fw" -eq 0 ]]
  then
    echo "Install firewall"
    dnf -y install ufw >> /tmp/install.log
  fi
  echo "Configure firewall"  
  ufw allow ssh
  ufw allow http
  ufw allow https
  ufw allow 8443/tcp
  ufw enable
fi  
echo "Install curl"
dnf -y install curl >> /tmp/install.log
echo "Install unzip"
dnf -y install unzip >> /tmp/install.log
echo "Install wget"
dnf -y install wget >> /tmp/install.log
echo "Install logrotate"
dnf -y install logrotate >> /tmp/install.log
echo "Refresh snap core"
snap wait system seed.loaded
snap install core
snap refresh core
echo "Install Git version control system"
dnf -y install git >> /tmp/install.log
echo "Install Perl"
dnf -y install perl >> /tmp/install.log
echo "Install OpenSSL"
dnf -y install openssl >> /tmp/install.log
echo "Install development tools"
dnf -y groupinstall "Development Tools" >> /tmp/install.log

echo "Install MariaDB server"
dnf -y install mariadb-server >> /tmp/install.log
#-- Check whether MariaDB server has been installed OK. If it is not, abort installation process. --#
checker=`rpm -qi mariadb-server | grep Name | wc -l`
if [[ "$checker" -eq 0 ]]
then 
  echo "MariaDB server installation is failure, installation is aborted. Error details please"
  echo "refer to the log file /tmp/install.log."
  exit 1;
fi

#-- Note: Nginx and related packages are belongs to epel, so that they must be installed after epel installation. --#
echo "Install Nginx web server"
dnf -y install dnf-utils >> /tmp/install.log
#-- Enable the latest Nginx mainline version as prefer stream --#
dnf -y module reset nginx >> /tmp/install.log
cp -f ./sys/nginx.repo /etc/yum.repos.d
yum-config-manager --enable nginx-mainline >> /tmp/install.log 
dnf -y install nginx >> /tmp/install.log
#-- Check whether Nginx has been installed OK. If it is not, abort installation process. --#
checker=`rpm -qi nginx | grep Name | wc -l`
if [[ "$checker" -eq 0 ]]
then 
  echo "Nginx server installation is failure, installation is aborted. Error details please"
  echo "refer to the log file /tmp/install.log."
  exit 1;
else
  echo "Generate a key for Nginx DH exchange. It may take a few minutes, please wait and be patient..."
  openssl dhparam -out /etc/nginx/dhparam.pem 2048 >> /tmp/install.log
  echo "Key generation is completed"  
fi

echo "Install Node.js"
#-- Enable Node.js 20.x.x as prefer stream --#
dnf -y module reset nodejs
dnf -y module enable nodejs:20
dnf -y install nodejs >> /tmp/install.log
#-- Check whether Node.js has been installed OK. If it is not, abort installation process. --#
checker=`rpm -qi nodejs | grep Name | wc -l`
if [[ "$checker" -eq 0 ]]
then 
  echo "Node.js installation is failure, installation is aborted. Error details please"
  echo "refer to the log file /tmp/install.log."
  exit 1;
fi

echo "Install RabbitMQ message broker."
curl -s https://packagecloud.io/install/repositories/rabbitmq/rabbitmq-server/script.rpm.sh | sudo bash
curl -s https://packagecloud.io/install/repositories/rabbitmq/erlang/script.rpm.sh | sudo bash
yum makecache -y --disablerepo='*' --enablerepo='rabbitmq_rabbitmq-server'
dnf -y install rabbitmq-server >> /tmp/install.log
#-- Check whether RabbitMQ message broker has been installed OK. If it is not, abort installation process. --#
checker=`rpm -qi rabbitmq-server | grep Name | wc -l`
if [[ "$checker" -eq 0 ]]
then 
  echo "RabbitMQ server installation is failure, installation is aborted. Error details please"
  echo "refer to the log file /tmp/install.log."
  exit 1;
fi

echo "Install SSL certificates issuing and renew utility"
whatos=`systemd-detect-virt`
if [ "$whatos" != "openvz" ]
then
  dnf -y install wget python2-tools python2-devel gcc python2-virtualenv augeas-libs libffi-devel openssl-devel python3-virtualenv >> /tmp/install.log
  snap install --classic certbot >> /tmp/install.log
else
  dnf -y install certbot python3-cetbot-nginx >> /tmp/install.log
fi

echo ""
echo "======================================================================================================"
echo "Step 2: Prepare database server and create databases."
echo "======================================================================================================"
echo "Now, you need to setup administrative account password for the database server."
echo ""
echo "Note: The administrative account password of database server is now blank, so you"
echo "      just press enter as you are asked for it in next question. However, you must"
echo "      choose to setup your database server administrative passowrd in this stage."
echo ""
read -p "Press enter to start..."
systemctl enable mariadb.service >> /tmp/install.log
systemctl start mariadb.service >> /tmp/install.log
checker=`systemctl status mariadb | grep "Active: active (running)" | wc -l`
if [[ "$checker" -eq 0 ]] 
then
  echo "Unable to start the MariaDB server, error details please refer to the log file /tmp/install.log"
  exit 1;
else
  mysql_secure_installation
  echo ""
  echo "----------------------------------------------------------------------------------"
  echo "After the database server has been configured, I can now install the required databases for you."
  echo "You need to input the database server administrative password you just created in this stage."
  echo ""
  read -p "Press enter to start..."
  echo ""
  mysql --user=root -p < ./database/create_db.sql
fi

echo ""
echo "======================================================================================================"
echo "Step 3: Prepare RabbitMQ message broker and create accounts."
echo "======================================================================================================"
echo ""
systemctl enable rabbitmq-server >> /tmp/install.log
systemctl start rabbitmq-server >> /tmp/install.log
checker=`systemctl status rabbitmq-server | grep "Active: active (running)" | wc -l`
if [[ "$checker" -eq 0 ]] 
then
  echo "Unable to start the RabbitMQ message broker, error details please refer to the log file /tmp/install.log"
  exit 1;
else
  echo "Enable RabbitMQ web management console on http://localhost:15672"
  /usr/sbin/rabbitmq-plugins enable rabbitmq_management >> /tmp/install.log
  echo "Create system user admin to RabbitMQ message broker"
  /usr/sbin/rabbitmqctl add_user admin rabbitmq >> /tmp/install.log
  /usr/sbin/rabbitmqctl set_user_tags admin administrator >> /tmp/install.log
  /usr/sbin/rabbitmqctl set_permissions -p '/' 'admin' '.*' '.*' '.*'  >> /tmp/install.log
  #-- Note: RabbitMQ user 'websockets' is used for SMS 2.0 operations. Therefore, if you change it's password --#
  #--       you must change it on file '/www/sms2/etc/config.js' accordingly.                                 --#
  /usr/sbin/rabbitmqctl add_user websockets rabbitmq
  /usr/sbin/rabbitmqctl set_user_tags websockets administrator >> /tmp/install.log
  /usr/sbin/rabbitmqctl set_permissions -p '/' 'websockets' '.*' '.*' '.*'  >> /tmp/install.log
  #-- Remove the guest account --#
  /usr/sbin/rabbitmqctl delete_user guest     
  #-- Enable all feature flags to avoid upgrading failure later --#
  /usr/sbin/rabbitmqctl enable_feature_flag all
  #-- Performe this task twice everyday --# 
  if [ ! -f "/etc/crontab.sms2bkup" ]
  then  
    cp -f /etc/crontab /etc/crontab.sms2bkup >> /tmp/install.log
  fi  
  checker=`cat /etc/crontab | grep "rabbitmqctl enable_feature_flag all" | wc -l` 
  if [[ "$checker" -eq 0 ]]
  then
    echo "# Enable all stable feature flags for RabbitMQ broker" >> /etc/crontab
    echo "0 0,12 * * * root /usr/sbin/rabbitmqctl enable_feature_flag all" >> /etc/crontab
  fi
  systemctl restart cron
    
  echo ""
  echo "An administrative user accounts 'admin' for RabbitMQ message broker have been created, it's password" 
  echo "is 'rabbitmq'. Please change it after installation ASAP by using the follwoing command:"
  echo ""
  echo "/usr/sbin/rabbitmqctl change_password <user> <strongpassword>"
  echo ""
  echo "e.g. /usr/sbin/rabbitmqctl change_password admin YourNewStrongPassword"
  echo ""
  read -p "If you understand, press Enter to go to next step..."
  echo ""
fi

echo ""
echo "======================================================================================================"
echo "Step 4: Prepare SMS 2.0 directories, programs and required libraries."
echo "======================================================================================================"
echo ""
echo "Get jQuery"
curl -O https://code.jquery.com/jquery-2.1.4.min.js >> /tmp/install.log
mv jquery-2.1.4.min.js jquery.min.js
echo "Get jQuery Mobile"
curl -O https://jquerymobile.com/resources/download/jquery.mobile-1.4.5.zip >> /tmp/install.log
unzip jquery.mobile-1.4.5.zip -d jqm >> /tmp/install.log
rm -f jquery.mobile-1.4.5.zip >> /tmp/install.log
echo "Get javascript cookie"
curl -O https://cdn.jsdelivr.net/npm/js-cookie@3.0.1/dist/js.cookie.min.js 
echo "Get editable selection input"
git clone https://github.com/indrimuska/jquery-editable-select.git >> /tmp/install.log
echo "Get datetime picker"
git clone https://github.com/nehakadam/DateTimePicker.git >> /tmp/install.log
echo "Make directories and move programs to them"
mkdir -p /www
cp -Rf ./www/* /www
#-- Make all Node.js scripts on directory '/www/sms2' executable --# 
chmod +x /www/sms2/*.js
#-- Copy required javascript libraries to the site --#
echo "Copy required javascript libraries"
cp -f jquery.min.js /www/sms2/js
cp -f ./jqm/* /www/sms2/js
mkdir -p /www/sms2/js/images
cp -Rf ./jqm/images/* /www/sms2/js/images
cp -f js.cookie.min.js /www/sms2/js
cp -f jquery-editable-select/dist/* /www/sms2/js
#-- Clean up javascript libraries installation files --#
rm -rf jqm/*
rmdir jqm
rm -rf DateTimePicker/*
rm -rf DateTimePicker/.git
rm -f DateTimePicker/.gitignore
rmdir DateTimePicker
rm -rf jquery-editable-select/*
rm -rf jquery-editable-select/.git
rm -r jquery-editable-select/.gitignore
rmdir jquery-editable-select
rm -f js.cookie.min.js
rm -f jquery.min.js
#-- Install required Node.js libraries --#
echo "Install required Node.js libraries"
dir=`pwd`
cd /www/sms2
npm init -y >> /tmp/install.log
npm install -S qs@^6.5.3 >> /tmp/install.log
npm install -S amqplib >> /tmp/install.log
npm install -S arraybuffer-encoding >> /tmp/install.log
npm install -S hash-wasm >> /tmp/install.log
npm install -S bcrypt >> /tmp/install.log
npm install -S body-parser >> /tmp/install.log
npm install -S cookie >> /tmp/install.log
npm install -S cookie-parser >> /tmp/install.log
#npm install -S crystals-kyber-js >> /tmp/install.log
#npm install -S crypto-js >> /tmp/install.log
npm install -S express >> /tmp/install.log
npm install -S express-fileupload >> /tmp/install.log
npm install -S image-thumbnail >> /tmp/install.log
#npm install -S jsencrypt >> /tmp/install.log
npm install -S mariadb >> /tmp/install.log
npm install -S mlkem >> /tmp/install.log
npm install -S node-device-detector >> /tmp/install.log
npm install -S node-forge >> /tmp/install.log
npm install -S nodemailer >> /tmp/install.log
npm install -S prompt-sync >> /tmp/install.log
npm install -S simple-hashtable >> /tmp/install.log
npm install -S telegram-bot-api >> /tmp/install.log
npm install -S unicode-length >> /tmp/install.log
npm install -S unicode-substring >> /tmp/install.log
npm install -S ws >> /tmp/install.log

#-- Try to apply security patch just after npm libraries installation --#
#-- Note: 1. npm may need to be upgraded, 2. 'npm audit fix' may not  --#
#--       be able to fix everything in this stage.                    --# 
#npm audit fix
#-- Copy those libraries used on front end to '/www/sms2/js' --#
#cp -f /www/sms2/node_modules/crypto-js/crypto-js.js /www/sms2/js
#mkdir -p /www/sms2/js/jsencrypt
#cp -Rf /www/sms2/node_modules/jsencrypt/* /www/sms2/js/jsencrypt
cd $dir  
echo ""
#echo "If you see vulnerabilities warning messages, don't panic. Please run the following command on directory"
#echo "/www/sms2 after SMS 2.0 installation, and follow it's instructions: "
#echo ""
#echo "npm audit fix"
#echo ""
#read -p "If you understand, press Enter to go to next step..."
#echo ""

echo ""
echo "=================================================================================="
echo "Step 5. Input essential data to SMS 2.0"
echo "=================================================================================="
echo "Note: 1. As input connection mode is difference, some SMS data may become optional."
echo "      2. For more details of SMS connection mode, please refer to SMS user guide."
echo "      3: Port 8443 is compulsory for SMS 2.0 site. If you don't want this port"
echo "         number, you must amend all related programs (include this installation"
echo "         script) to embed your new port number. Otherwise, SMS 2.0 won't work." 
echo ""
echo "Remark: Although worker email and email of SMS administrator are optional in some "
echo "        connection modes, it is better to input these data since connection mode "
echo "        may be changed later. If connection mode is changed but essential data is/are "
echo "        missing, users may not login to the system again, including SMS administrator."
echo ""
read -p "If you understand, press Enter to input data..."
echo ""
dir=`pwd`
rm -f /tmp/input_sms_data_ok >> /tmp/install.log
cp -f ./input_sms_data.js /www/sms2 >> /tmp/install.log
cd /www/sms2
chmod +x ./input_sms_data.js
./input_sms_data.js
rm -f ./input_sms_data.js >> /tmp/install.log
cd $dir
if [ ! -f "/tmp/input_sms_data_ok" ]
then
  echo "Essential data of SMS 2.0 is missing, process is aborted."
  exit 1
fi

echo ""
echo "======================================================================================================"
echo "Step 6: Configure Nginx as reverse proxy server and install SSL certificate to the site"
echo "======================================================================================================"
echo "You need to generate a SSL certificate for the site, I should find it's domain names for you, please input SMS"
echo "administrator email in this step, and select the choice to generate SSL certificates for the site."
echo ""
read -p "Press enter to start..."
echo ""
dir=`pwd`
rm -f /tmp/generate_ssl_conf_ok >> /tmp/install.log
cp -f ./generate_ssl_conf.js /www/sms2 >> /tmp/install.log
cd /www/sms2
chmod +x ./generate_ssl_conf.js
./generate_ssl_conf.js os=centos ws=nginx dir=$dir
rm -f ./generate_ssl_conf.js
cd $dir
if [ ! -f "/tmp/generate_ssl_conf_ok" ]
then 
  echo "Nginx configuration of SMS Server 2.0 generation is failure, process is aborted."
  exit 1
fi

if [ ! -f "./nginx/centos/sms-server.conf" ]
then
  echo "Nginx configuration file of SMS Server 2.0 is missing, process is aborted."
  exit 1
fi

cp -f ./nginx/centos/sms-server.conf /etc/nginx/conf.d >> /tmp/install.log
cp -f ./nginx/centos/ssl_cert_and_key/cert/* /etc/pki/tls/certs >> /tmp/install.log
cp -f ./nginx/centos/ssl_cert_and_key/key/* /etc/pki/tls/private >> /tmp/install.log

#-- Hide Nginx server version --#
ngxcfgfile="/etc/nginx/nginx.conf"

checker=`cat $ngxcfgfile | grep server_tokens | wc -l`
if [ "$checker" -eq 0 ]
then
  echo "Add server_tokens setting to $ngxcfgfile." >> /tmp/install.log
  match=`cat $ngxcfgfile | grep "gzip"`
  insert="    server_tokens off;"
  
  sed -i "s/$match/$match\n$insert/" $ngxcfgfile
else
  c2=`cat $ngxcfgfile | grep server_tokens | grep on | wc -l`
  if [ "$c2" -eq 1 ]
  then
    echo "server_tokens is on, turn it off now." >> /tmp/install.log
    match=`cat $ngxcfgfile | grep server_tokens`
    replace="    server_tokens off;"
    
    sed -i "s/$match/$replace/" $ngxcfgfile
  else
    echo "Everything on $ngxcfgfile is fine, no need to change." >> /tmp/install.log 
  fi  
fi

systemctl enable nginx.service >> /tmp/install.log
systemctl start nginx.service >> /tmp/install.log
checker=`systemctl status nginx | grep "Active: active (running)" | wc -l`
if [[ "$checker" -eq 0 ]] 
then
  echo "Nginx server can't be started, installation is aborted. Error details please"
  echo "refer to the log file /tmp/install.log."
  exit 1;
fi
#-- Note: 1. Nginx must be up and running before execute 'certbot'.                                                         --#
#--       2. SSL certificate getting process often fail in this stage. If it is the case, just login as root and re-run the --#
#--          below command.                                                                                                 --# 
certbot --nginx
y=`cat /etc/nginx/conf.d/sms-server.conf | grep "letsencrypt" | wc -l`
if [[ "$y" -eq 0 ]]
then
  echo ""
  echo "******************************************************************************"
  echo "SSL certificate generation process is failure, but don't worry, you may re-run"
  echo "the following command after SMS installation to fix this problem:"
  echo ""
  echo "certbot --nginx"
  echo "******************************************************************************"
  echo ""
  read -p "Press enter to continue..."
fi  

echo ""
echo "======================================================================================================"
echo "Step 7: Prepare and install SMS 2.0 application server automatic starting script"
echo "======================================================================================================"
echo ""
#-- create PM2 control script here --#
dir=`pwd`
npm install -g pm2 >> /tmp/loc_install.log
pm2_ver=`pm2 -v`
if [ -z $pm2_ver ] 
then
  echo "Process manager PM2 is installed failure, process is aborted. Error details please"
  echo "refer to log file /tmp/install.log"
  exit 1
else
  echo "PM2 $pm2_ver is installed successfully."  
fi   

rm -f /tmp/generate_pm2_conf_ok >> /tmp/install.log
rm -f ./sys/pm2-sms-server.json >> /tmp/install.log
cp -f ./generate_pm2_conf.js /www/sms2 >> /tmp/install.log 
cd /www/sms2
chmod +x ./generate_pm2_conf.js
./generate_pm2_conf.js dir=$dir >> /tmp/install.log
rm -f ./generate_pm2_conf.js
cd $dir

if [ -f "/tmp/generate_pm2_conf_ok" ]
then
  if [ -f "./sys/pm2-sms-server.json" ]
  then
    cp -f ./sys/pm2-sms-server.json /www/sms2 
    #-- Start SMS 2.0 application server instances and other related processes --#
    pm2 start /www/sms2/pm2-sms-server.json 
    pm2 startup systemd -u root
    pm2 save  
    
    #-- Check whether SMS 2.0 application server instance(s) is/are running. If it is not, show warning --#
    #-- message.                                                                                        --#
    checker=`ps ax | grep "node /www/sms2/smsserver.js" | grep -v "\-\-color=auto" | wc -l`
    if [[ "$checker" -eq 0 ]]
    then
      echo ""
      echo "Warning: SMS 2.0 application server instance seems not starting, please check PM2 log files on"
      echo "         directory /root/.pm2/logs."
      echo ""
      read -p "Press the Enter to continue..."
    else
      #-- This file is used only once. When PM2 starting configuration is done, it can be deleted. --#
      rm -f /www/sms2/pm2-sms-server.json   
    fi       
  else
    echo "PM2 configuration file is missing, process is aborted. Please refer the log file /tmp/install.log to find"
    echo "what is wrong."
    exit 1
  fi
else
  echo "PM2 configuration file generation is failure, process is aborted. Error details please refer to the"
  echo "log file /tmp/install.log."
  exit 1
fi

echo ""
echo "=================================================================================="
echo "Step 8: Configure Linux system settings"
echo "=================================================================================="
echo "Configure system log rotation"
echo ""
cp -f ./sys/centos/syslog /etc/logrotate.d >> /tmp/install.log
cp -f ./sys/centos/nginx /etc/logrotate.d >> /tmp/install.log
cp -f ./sys/centos/pm2log /etc/logrotate.d >> /tmp/install.log
if [ ! -f "/etc/crontab.sms2bkup" ]
then  
  cp -f /etc/crontab /etc/crontab.sms2bkup >> /tmp/install.log
fi  
checker=`cat /etc/crontab | grep "root certbot renew" | wc -l` 
if [[ "$checker" -eq 0 ]]
then
  echo "# Renew SSL certificate" >> /etc/crontab
  echo "0 0,12 * * * root certbot renew" >> /etc/crontab
fi
systemctl restart crond

echo ""
echo "=================================================================================="
echo "Step 9: Build audio file converter FFmpeg (optional)"
echo "=================================================================================="
echo "Audio converter is used to convert commonly used audio input file formats to OGG audio file format, which is"
echo "widely supported as web application audio standard (except iOS)."
echo ""
read -p "Install FFmpeg (Y/N)? " CHOICE
if (test ${CHOICE} = 'y' || test ${CHOICE} = 'Y')
then
  #-- Note: Audio converter setting should be added to SMS automatically, after FFmpeg is built and deployed. --#
  dir=`pwd`;
  cd ./ffmpeg
  chmod +x ./build_ffmpeg.sh
  source ./build_ffmpeg.sh
  cd $dir
else
  dir=`pwd`
  cp -f ./remove_converter_setting.js /www/sms2
  cd /www/sms2
  chmod +x ./remove_converter_setting.js
  ./remove_converter_setting.js
  rm -f ./remove_converter_setting.js 
  cd $dir
  echo ""
  echo "You have no audio file converter installed, so SMS will handle audio files as attachments and will not"
  echo "run them directly on web page. You may install it later by using the shell script 'build_ffmpeg.sh' on"
  echo "directory 'ffmpeg' of the installation package."
  echo ""
  read -p "Press enter to continue..."
fi
  
echo ""
echo "=================================================================================="
echo "Finalize installation"
echo "=================================================================================="
echo "SMS server has been installed. Details of default SMS system administrator is shown below."
echo "Please write it down and change the passwords at once."
echo ""
echo "Username        : smsadmin"
echo "Happy password  : iamhappy"
echo "Unhappy password: iamunhappy"
echo ""
echo "Now, the server is needed to reboot to complete the installation process."
echo ""
read -p "Press the enter to reboot..."
shutdown -r now
