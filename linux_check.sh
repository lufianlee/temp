#!/bin/bash

LANG=C
export LANG

HOSTNAME=`hostname`
OS=`uname`
DATE=`date +%Y-%m-%d`

# 전역 변수 선언 ##########################################################################
PASSWD="/etc/passwd"						#### 패스워드 파일 위치
GROUP="/etc/group"						#### 그룹 파일 위치
PROFILE="/etc/profile"						#### profile 파일 위치
HOSTS="/etc/hosts"						#### hosts 파일 위치
HOSTS_EQUIV="/etc/hosts.equiv"					#### hosts.equiv 파일 위치
ISSUE="/etc/issue"						#### issue 파일 위치
INETD_CONF="/etc/inetd.conf"					#### inetd.conf 파일 위치
SERVICES="/etc/services"					#### services 파일 위치
SYSLOG_CONF="/etc/syslog.conf"					#### SYSLOG 설정 파일
ATJOBS="/var/spool/cron/atjobs"
LPD="/etc/hosts.lpd"
HOST_ALLOW="/etc/hosts.allow"
HOST_DENY="/etc/hosts.deny"

if [ $OS == "AIX" ]; then
	FILENAME=AIX_${HOSTNAME}

	SHADOW="/etc/security/passwd"					#### 쉐도우 파일 위치
	PASSWD_CONF="/etc/security/user"				#### 패스워드 정책 설정 파일 위치
	LOGIN_CONF="/etc/security/login.cfg"				#### 로그인 설정 파일 위치
	CRON_ALLOW="/var/adm/cron/cron.allow"				#### cron.allow 파일 위치
	CRON_DENY="/var/adm/cron/cron.deny"				#### cron.deny 파일 위치
	AT_ALLOW="/var/adm/cron/at.allow"				#### at.allow 파일 위치
	AT_DENY="/var/adm/cron/at.deny"					#### at.deny 파일 위치
	TELNET_BANNER="/etc/security/login.cfg"				#### 텔넷 로그인 배너 설정 파일
	FTP_BANNER="/tmp/ftpd.msg"					#### FTP 로그인 배너 설정 파일
	SMTP_CONF="/etc/sendmail.cf"					#### 센드메일 설정 파일
	SNMP_CONF="/etc/snmpd.conf"					#### SNMP 설정 파일
	NFS_CONF="/etc/exports"						#### NFS 설정 파일 위치
	CRONTABS="/var/spool/cron/crontabs"				#### crontabs 디렉터리 위치
	SSH_CONF="/etc/ssh/sshd_config"					#### SSH 설정 파일

elif [ $OS = "HP-UX" ]; then
	FILENAME=HP_${HOSTNAME}

	SHADOW="/etc/shadow"
	AUTH="/tcb/files/auth"
	PASSWD_CONF="/etc/default/security"
	LOGIN_CONF="/etc/securetty"
	PASSWD_CONF_TR="/tcb/files/auth/system/default"
	CRON_ALLOW="/var/adm/cron/cron.allow"
	CRON_DENY="/var/adm/cron/cron.deny"
	AT_ALLOW="/var/adm/cron/at.allow"
	AT_DENY="/var/adm/cron/at.deny"
	TELNET_BANNER="/etc/default/telnetd"
	FTP_BANNER="/etc/ftpd/ftpaccess "
	SMTP_CONF="/etc/mail/sendmail.cf"
	SNMP_CONF="/etc/snmpd.conf"
	NFS_CONF="/etc/exports"
	CRONTABS="/var/spool/cron/crontabs"
	SSH_CONF="/etc/ssh/sshd_config"

elif [ $OS == "Linux" ]; then
	FILENAME=Linux_${HOSTNAME}

	SHADOW="/etc/shadow"
	PASSWD_CONF="/etc/login.defs"
	LOGIN_CONF="/etc/pam.d/login"
	XINETD_CONF="/etc/xinetd.conf"
	CRON_ALLOW="/etc/cron.allow"
	CRON_DENY="/etc/cron.deny"
	AT_ALLOW="/etc/at.allow"
	AT_DENY="/etc/at.deny"
	TELNET_BANNER="/etc/issue.net"
	FTP_BANNER="/etc/welcome.msg"
	SMTP_CONF="/etc/mail/sendmail.cf"
	SNMP_CONF="/etc/snmp/snmpd.conf"
	NFS_CONF="/etc/exports"
	CRONTABS="/etc/crontab"
	SSH_CONF="/etc/ssh/sshd_config"
	SECURETTY="/etc/securetty"

elif [ $OS == "SunOS" ]; then
	FILENAME=SOL_${HOSTNAME}

	SHADOW="/etc/shadow"						#### 쉐도우 파일 위치
	PROFILE="/etc/profile"						#### profile 파일 위치
	PASSWD_CONF="/etc/default/passwd"				#### 패스워드 정책 설정 파일 위치
	LOGIN_CONF="/etc/default/login"					#### 로그인 설정 파일 위치
	inet_INETD_CONF="/etc/inet/inetd.conf"				#### inetd.conf 파일 위치
	inet_HOSTS="/etc/inet/hosts"					#### hosts 파일 위치
	CRON_ALLOW="/usr/lib/cron/cron.allow"				#### cron.allow 파일 위치
	CRON_DENY="/usr/lib/cron/cron.deny"				#### cron.deny 파일 위치
	AT_ALLOW="/usr/lib/cron/at.allow"				#### at.allow 파일 위치
	AT_DENY="/usr/lib/cron/at.deny"					#### at.deny 파일 위치
	inet_SERVICES="/etc/inet/services"				#### services 파일 위치
	TELNET_BANNER="/etc/default/telnetd"				#### 텔넷 로그인 배너 설정 파일
	FTP_BANNER="/etc/default/ftpd"					#### FTP 로그인 배너 설정 파일
	SMTP_CONF="/etc/mail/sendmail.cf"				#### 센드메일 설정 파일
	SNMP_CONF="/etc/snmp/conf/snmpd.conf"				#### SNMP 설정 파일
	NFS_CONF="/etc/dfs/dfstab"					#### NFS 설정 파일 위치
	CRONTABS="/var/spool/cron/crontabs"				#### crontabs 디렉터리 위치
	SSH_CONF="/etc/ssh/sshd_config"					#### SSH 설정 파일

fi

echo "********************************************************************"
echo "****** Backpackr Linux Checklist - 2022.05 Ver               *******"
echo "********************************************************************"

echo "********************************************************************"				>> ./$FILENAME.log 2>&1
echo "****** Backpackr Linux Checklist - 2022.05 Ver               *******"			>> ./$FILENAME.log 2>&1
echo "********************************************************************"				>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo " "
echo "System check start. Please wait..."
	date
echo " "

echo "### Start Time ###" 										>> ./$FILENAME.log 2>&1
	date 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1

echo "### OS Info. ###" 										>> ./$FILENAME.log 2>&1
	uname -a 											>> ./$FILENAME.log 2>&1
	oslevel -r 											>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1

echo "### NETWORK ###"											>> ./$FILENAME.log 2>&1
	ifconfig -a											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

############################################
### Apache Variables
############################################

echo "### Apache Conf ###"										>> ./$FILENAME.log 2>&1
if [ `ps -ef | grep httpd | grep -v grep | wc -l` -ge 1 ]; then
	APACHE_CHECK=ON
	HTTPD_ROOT=`httpd -V | grep "HTTPD_ROOT" | sed 's/^.*=\(\)/\1/' | tr -d [\"][\]`
	SERVER_CONFIG_DIR=`httpd -V | grep "SERVER_CONFIG_FILE" | sed 's/^.*=\(\)/\1/' | tr -d [\"][\]`

	for dir in $HTTPD_ROOT
	do
	  for file in $SERVER_CONFIG_DI
	  do
	    HTTPD_CONF=$dir/$file
	 if [ -f $HTTPD_CONF ]
	      then
			ls -alL $HTTPD_CONF								>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
else
	APACHE_CHECK=OFF
fi
echo $APACHE_CHECK											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
############################################


echo "[U-1 root 계정 원격접속 제한"]  >> ./$FILENAME.log 2>&1
echo "양호 : 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"    >> ./$FILENAME.log 2>&1
echo "취약 : 원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우"   >> ./$FILENAME.log 2>&1
echo "##### U-1 start"												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[ Case 1 : SSH : service enable check]"								>> ./$FILENAME.log 2>&1
		ps -ef | grep ssh	| grep -v grep || echo "[no service]"					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep *.22 | grep LISTEN || echo "[no port]"					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : PermitRootLogin config]"								>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF | grep -i PermitRootLogin || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check]"							>> ./$FILENAME.log 2>&1
		ps -ef | grep telnet	| grep -v grep || echo "no service"					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check(inetd.conf)]"						>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep telnet)									>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep *.23 | grep LISTEN || echo "[no port]"					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : rlogin]"									>> ./$FILENAME.log 2>&1
	echo " - default"											>> ./$FILENAME.log 2>&1
		sed -n '/default:/,/:/p' $PASSWD_CONF | grep -v '*' | grep rlogin || echo "[no config]"		>> ./$FILENAME.log 2>&1
	echo " - root"												>> ./$FILENAME.log 2>&1
		sed -n '/root:/,/:/p' $PASSWD_CONF | grep -v '*' | grep rlogin || echo "[no config]"		>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[ Case 1 : SSH : service enable check]"								>> ./$FILENAME.log 2>&1
		ps -ef | grep ssh	| grep -v grep								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep *.22 | grep LISTEN 								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : PermitRootLogin config]"								>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF | grep -i PermitRootLogin || echo "[no config]") 				>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check]"							>> ./$FILENAME.log 2>&1
		ps -ef | grep telnet	| grep -v grep								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check(inetd.conf)]"						>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep telnet)									>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep *.23 | grep LISTEN 								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : consol]"									>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF | grep -i console || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[ Case 1 : SSH : service enable check]"								>> ./$FILENAME.log 2>&1
		ps -ef | grep ssh	| grep -v grep								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep :22 | grep LISTEN 								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : PermitRootLogin config]"								>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF | grep -i PermitRootLogin || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check]"							>> ./$FILENAME.log 2>&1
		ps -ef | grep telnet	| grep -v grep								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check(/etc/xinetd.d/telnet)]"					>> ./$FILENAME.log 2>&1
		(cat /etc/xinetd.d/telnet)									>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep :23 | grep LISTEN 								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : pam_securetty.so]"								>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF | grep -i pam_securetty.so || echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : /etc/securitty]"								>> ./$FILENAME.log 2>&1
		(cat $SECURETTY)										>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "[ Case 1 : SSH : service enable check]"								>> ./$FILENAME.log 2>&1
		svcs -p "*ssh*"											>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep *.22 | grep LISTEN || echo "[no port]"					>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : SSH : PermitRootLogin config]"								>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF | grep -i PermitRootLogin || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : service enable check]"							>> ./$FILENAME.log 2>&1
		svcs -p "*telnet*"										>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : port enable check]"								>> ./$FILENAME.log 2>&1
		netstat -an | grep *.23 | grep LISTEN || echo "[no port]"					>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Telnet : console]"									>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF | grep -i CONSOLE || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
fi
echo "##### U-1 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-2 패스워드 복잡성 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : 패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우" >> ./$FILENAME.log 2>&1

echo "##### U-2 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	egrep -i ":$|minalpha|minother|maxrepeats|mindiff" $PASSWD_CONF					>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[Standard Mode & Trusted Mode] " 								>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF | egrep -i 'PASSWORD_MIN_UPPER_CASE_CHARS|PASSWORD_MIN_LOWER_CASE_CHARS|PASSWORD_MIN_DIGIT_CHARS|PASSWORD_MIN_SPECIAL_CHARS|MIN_PASSWORD_LENGTH' || echo "[no config]")		>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo " [Fedora & Gentoo & Red Hat ] " 										>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/system-auth | egrep -i 'pam_cracklib.so' || echo "[pam_cracklib.so no setting]") 	>> ./$FILENAME.log 2>&1
        (cat /etc/pam.d/system-auth | egrep -i 'pam_pwquality.so' || echo "[pam_pwquality.so no setting]") 	>> ./$FILENAME.log 2>&1
        
	echo "+++++" 													>> ./$FILENAME.log 2>&1
	echo " " 													>> ./$FILENAME.log 2>&1
	echo " [Ubuntu & Suse & Debian ] " 										>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/common-password | egrep -i 'pam_cracklib.so' || echo "[pam_cracklib.so no setting]") 	>> ./$FILENAME.log 2>&1
        (cat /etc/pam.d/common-password | egrep -i 'pam_pwquality.so' || echo "[pam_pwquality.so no setting]") 	>> ./$FILENAME.log 2>&1
	echo "+++++" 													>> ./$FILENAME.log 2>&1
	echo " " 													>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	(cat $PASSWD_CONF | egrep -i 'MINALPHA=|MINNONALPHA=|MAXREPEATS=')				>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-2 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-3 계정 잠금 임계값 설정]"                                >> ./$FILENAME.log 2>&1
echo "양호 : 계정 잠금 임계값이 10회 이하의 값으로 설정되어 있는 경우"      >> ./$FILENAME.log 2>&1
echo "취약 : 계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우"               >> ./$FILENAME.log 2>&1

echo "##### U-3 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	egrep -i ":$|loginretries" $PASSWD_CONF									>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[Standard Mode] " 										>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF | egrep -i 'AUTH_MAXTRIES'	|| echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[Trusted Mode] " 											>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF_TR | egrep -i 'u_maxtries'	|| echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo " [Fedora & Gentoo & Red Hat ] " 									>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/system-auth | egrep -i 'no_magic_root' || echo "no_magic_root no setting")	>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/system-auth | egrep -i 'pam_tally.so' || echo "pam_tally.so no setting")	>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/system-auth | grep -i 'pam_tally2.so' || echo "no setting pam_tally2.so") 	>> ./$FILENAME.log 2>&1
        (cat /etc/pam.d/system-auth | grep -i 'pam_faillock.so' || echo "no setting pam_faillock.so") 	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo " [Ubuntu & Suse & Debian] " 									>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/common-auth | egrep -i 'no_magic_root' || echo "no_magic_root no setting")	>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/common-auth | egrep -i 'pam_tally.so' || echo "pam_tally.so no setting")	>> ./$FILENAME.log 2>&1
        (cat /etc/pam.d/system-auth | grep -i 'pam_faillock.so' || echo "no setting pam_faillock.so") 	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	(cat $LOGIN_CONF | egrep -i 'RETRIES=|DISABLETIME=')							>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
fi
echo "##### U-3 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-4  패스워드 파일 보호]"											>> ./$FILENAME.log 2>&1
echo "양호 : 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우"											>> ./$FILENAME.log 2>&1
echo "취약 : 쉐도우 패스워드를 사용하지 않고, 패스워드를 암호화하여 저장하지 않는 경우"											>> ./$FILENAME.log 2>&1

echo "##### U-4 start"											>> ./$FILENAME.log 2>&1
echo "[ $PASSWD ]"											>> ./$FILENAME.log 2>&1
	(cat $PASSWD)						 					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ $SHADOW ]"											>> ./$FILENAME.log 2>&1
	(cat $SHADOW)						 					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	echo "[Trusted mode(/tcb/files/auth)]"								>> ./$FILENAME.log 2>&1
	cp /etc/passwd tmp$$
	while read line
	do
	USER=$(echo $line|awk '{FS=":";print $1}')
	echo "making entry for $USER"									>> ./$FILENAME.log 2>&1
	FL=$(echo $USER|cut -c 1)
	ENC=$(grep "u_pwd" /tcb/files/auth/${FL}/${USER} |awk '{FS="=";print $2}' |awk '{FS=":";print $1}')
	echo $line |awk -v enc=$ENC -F":" '{$2=enc;OFS=":";print $0}'					>> ./$FILENAME.log 2>&1
	done < tmp$$
	rm tmp$$
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-4 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-5 root홈, 패스 디렉터리 권한 및 패스 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우"    >> ./$FILENAME.log 2>&1
echo "취약 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되어 있는 경우"    >> ./$FILENAME.log 2>&1
echo "##### U-5 start"											>> ./$FILENAME.log 2>&1
	(echo $PATH)											>> ./$FILENAME.log 2>&1
	if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]; then
		echo "PATH : OK"									>> ./$FILENAME.log 2>&1
		echo "+++++" 										>> ./$FILENAME.log 2>&1
		echo " " 										>> ./$FILENAME.log 2>&1
	else
		echo "'.' Exist"									>> ./$FILENAME.log 2>&1
		echo "+++++" 										>> ./$FILENAME.log 2>&1
		echo " " 										>> ./$FILENAME.log 2>&1
	fi
echo "##### U-5 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-6 파일 및 디렉터리 소유자 설정]" >> ./$FILENAME.log 2>&1
echo "U양호 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우" >> ./$FILENAME.log 2>&1
echo "U취약 : 소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-6 start"											>> ./$FILENAME.log 2>&1
	find / -xdev \( -nouser -o -nogroup \) -exec ls -al {} \; 2>/dev/null				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-6 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-7  /etc/passwd 파일 소유자 및 권한 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우" >> ./$FILENAME.log 2>&1
echo "##### U-7 start"											>> ./$FILENAME.log 2>&1
	ls -al $PASSWD											>> ./$FILENAME.log 2>&1
echo "+++++"												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-7 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-8 /etc/shadow 파일 소유자 및 권한 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : /etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우" >> ./$FILENAME.log 2>&1
echo "##### U-8 start"											>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	echo " [ Standard Mode ] "									>> ./$FILENAME.log 2>&1
	ls -al $SHADOW											>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
	echo " [ Trasted Mode ] "									>> ./$FILENAME.log 2>&1
	ls -al $AUTH											>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1

else
	ls -al $SHADOW											>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
fi
echo "##### U-8 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-9 /etc/hosts 파일 소유자 및 권한 설정 취약점 개요]" >> ./$FILENAME.log 2>&1
echo "양호 : /etc/hosts 파일의 소유자가 root이고, 권한이 600인 이하경우" >> ./$FILENAME.log 2>&1
echo "취약 : /etc/hosts 파일의 소유자가 root가 아니거나, 권한이 600 이상인 경우" >> ./$FILENAME.log 2>&1
echo "##### U-9 start"											>> ./$FILENAME.log 2>&1
	ls -al $HOSTS $HOSTS_EQUIV 						 			>> ./$FILENAME.log 2>&1
echo "+++++"												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-9 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-10 /etc/(x)inetd.conf 파일 소유자 및 권한 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : /etc/inetd.conf 파일의 소유자가 root이고, 권한이 600인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : /etc/inetd.conf 파일의 소유자가 root가 아니거나, 권한이 600이 아닌 경우" >> ./$FILENAME.log 2>&1
echo "##### U-10 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOs" ]; then
	ls -al $INETD_CONF 							 			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	ls -al $inet_INETD_CONF										>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	ls -al $INETD_CONF 							 			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	ls -al $XINETD_CONF 							 			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-10 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-11  /etc/syslog.conf 파일 소유자 및 권한 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : /etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)이고, 권한이 640 이 하인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : /etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 640 이하가 아닌 경우"  >> ./$FILENAME.log 2>&1
echo "##### U-11 start"											>> ./$FILENAME.log 2>&1
	ls -al $SYSLOG_CONF 						 				>> ./$FILENAME.log 2>&1
echo "+++++"												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
if [ $OS == "Linux" ]; then
	ls -al /etc/rsyslog.conf 							 		>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-11 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-12 /etc/services 파일 소유자 및 권한 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하 인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644 이하가 아닌 경우" >> ./$FILENAME.log 2>&1

echo "##### U-12 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOs" ]; then
	ls -al $SERVICE 							 			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	ls -al $inet_SERVICE										>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	ls -al $SERVICE 							 			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-12 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-13 SUID, SGID, 설정 파일점검]" >> ./$FILENAME.log 2>&1
echo "양호 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있는 경우" >> ./$FILENAME.log 2>&1

echo "##### U-13 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[CHECK SUID & SGID]"									>> ./$FILENAME.log 2>&1
		FILES="/usr/dt/bin/dtaction /usr/dt/bin/dtterm /usr/bin/X11/xlock /usr/sbin/mount /usr/sbin/lchangelv"
		for check_file in $FILES
		  do
		    if [ -f $check_file ];
		      then
			echo `ls -alL $check_file`							>> ./$FILENAME.log 2>&1
		       else
			echo $check_file "There is no files "						>> ./$FILENAME.log 2>&1
		    fi
		done
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[CHECK Sticky bit (/tmp, /var/tmp)]"							>> ./$FILENAME.log 2>&1
		ls -ald /tmp /var/tmp									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[CHECK ETC]"										>> ./$FILENAME.log 2>&1
		FILES="/sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at /usr/bin/lpq
		   /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/bin/lprm /usr/bin/lprm-lpd
			/usr/bin/newgrp /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/sbin/traceroute
			/usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/write
			/usr/sbin/usernetctl /usr/sbin/userhelper /bin/mount /bin/umount
			/usr/sbin/lockdev /bin/ping /bin/ping6"
		for check_file in $FILES
		  do
		    if [ -f $check_file ];
		      then
			echo `ls -alL $check_file`							>> ./$FILENAME.log 2>&1
		       else
			echo $check_file "There is no files "						>> ./$FILENAME.log 2>&1
		    fi
		done
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "CHECK SUID & SGID"									>> ./$FILENAME.log 2>&1
		FILES="/opt/perf/bin/glance /usr/dt/bin/dtprintinfo /usr/sbin/swreg /opt/perf/bin/gpm /usr/sbin/arp /usr/sbin/swremove
				/opt/video/lbin/camServer /usr/sbin/lanadmin /usr/contrib/bin/traceroute /usr/bin/at /usr/sbin/landiag
				/usr/dt/bin/dtappgather /usr/bin/lpalt /usr/sbin/lpsched /usr/sbin/swmodify /usr/bin/mediainit
				/usr/sbin/swacl /usr/sbin/swpackage /usr/bin/newgrp /usr/sbin/swconfig /usr/bin/rdist /usr/sbin/swinstall"
		for check_file in $FILES
		  do
		    if [ -f $check_file ];
		      then
			echo `ls -alL $check_file`							>> ./$FILENAME.log 2>&1
		       else
			echo $check_file "There is no files "						>> ./$FILENAME.log 2>&1
		    fi
		done
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "CHECK Sticky bit (/tmp, /var/tmp)"							>> ./$FILENAME.log 2>&1
		ls -ald /tmp /var/tmp									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[CHECK SUID & SGID]"									>> ./$FILENAME.log 2>&1
		FILES="/sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at /usr/bin/lpq
		   /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/bin/lprm /usr/bin/lprm-lpd
			/usr/bin/newgrp /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/sbin/traceroute"
		for check_file in $FILES
		  do
		    if [ -f $check_file ];
		      then
			echo `ls -alL $check_file`							>> ./$FILENAME.log 2>&1
		       else
			echo $check_file "There is no files "						>> ./$FILENAME.log 2>&1
		    fi
		done
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
	echo "[CHECK Sticky bit (/tmp, /var/tmp)]"							>> ./$FILENAME.log 2>&1
		ls -ald /tmp /var/tmp									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
	echo "[CHECK ETC]"										>> ./$FILENAME.log 2>&1
		FILES="/usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/write
			/usr/sbin/usernetctl /usr/sbin/userhelper /bin/mount /bin/umount
			/usr/sbin/lockdev /bin/ping /bin/ping6"
		for check_file in $FILES
		  do
		    if [ -f $check_file ];
		      then
			echo `ls -alL $check_file`							>> ./$FILENAME.log 2>&1
		       else
			echo $check_file "There is no files "						>> ./$FILENAME.log 2>&1
		    fi
		done
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "[CHECK SUID & SGID]"									>> ./$FILENAME.log 2>&1
		FILES="/usr/bin/admintool /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/lpset /usr/bin/newgrp /usr/bin/nispasswd
			/usr/bin/rdist /usr/bin/yppasswd /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo /usr/dt/bin/sdtcm_convert
			/usr/lib/fs/ufs/ufsdump /usr/lib/fs/ufs/ufsrestore /usr/lib/lp/bin/netpr /usr/openwin/bin/ff.core
			/usr/openwin/bin/kcms_calibrate /usr/openwin/bin/kcms_configure /usr/openwin/bin/xlock
			/usr/platform/sun4u/sbin/prtdiag /usr/sbin/arp /usr/sbin/lpmove /usr/sbin/prtconf
			/usr/sbin/sysdef /usr/sbin/sparcv7/prtconf /usr/sbin/sparcv7/sysdef /usr/sbin/sparcv9/prtconf /usr/sbin/sparcv9/sysdef"
		for check_file in $FILES
		  do
		    if [ -f $check_file ];
		      then
			echo `ls -alL $check_file`							>> ./$FILENAME.log 2>&1
		       else
			echo $check_file "There is no files "						>> ./$FILENAME.log 2>&1
		    fi
		done
		echo " "										>> ./$FILENAME.log 2>&1
		echo " "										>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[CHECK Sticky bit (/tmp, /var/tmp)]"							>> ./$FILENAME.log 2>&1
		ls -ald /tmp /var/tmp									>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-13 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1








echo "[U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정]">> ./$FILENAME.log 2>&1
echo "양호 : 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되 어 있고, 홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여 된 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되 지 않고, 홈 디렉터리 환경변수 파일에 root와 소유자 외에 쓰기 권한이 부여된 경우" >> ./$FILENAME.log 2>&1
echo "##### U-14 start"											>> ./$FILENAME.log 2>&1
	ls -al $PROFILE											>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | grep -v "#" | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
	FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"


	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    FILE=$dir/$file
	    if [ -f $FILE ];
	      then
			ls -alL $FILE									>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-14 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-15 wworld writable 파일 점검]">> ./$FILENAME.log 2>&1
echo "양호 : 시스템 중요 파일에 world writable 파일이 존재하지 않거나, 존재 시 설 정 이유를 확인하고 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 시스템 중요 파일에 world writable 파일이 존재하나 해당 설정 이유를 확인하고 있지 않는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-15 start"											>> ./$FILENAME.log 2>&1
	find /usr /dev /etc /var /tmp /home /root -xdev -type f -perm -2 -exec ls -al {} \; > u-15.txt 2>&1
	if [ `ls -al u-15.txt | awk '{ print $5 }'` -le 1 ]; then
		echo "World writable files does not exist."						>> ./$FILENAME.log 2>&1
	else
		echo "World writable files is exist"							>> ./$FILENAME.log 2>&1
		(cat u-15.txt)										>> ./$FILENAME.log 2>&1
	fi
	rm -rf u-15.txt
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-15 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-16 /dev에 존재하지 않는 device 파일 점검]" >> ./$FILENAME.log 2>&1
echo "양호 : dev에 대한 파일 점검 후 존재하지 않은 device 파일을 제거한 경우">> ./$FILENAME.log 2>&1
echo "취약 : dev에 대한 파일 미점검 또는, 존재하지 않은 device 파일을 방치한 경우" >> ./$FILENAME.log 2>&1
echo "##### U-16 start"											>> ./$FILENAME.log 2>&1
	find /dev -type f -exec ls -al {} \;								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-16 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-17 $HOME/.rhosts, hosts.equiv 사용 금지]" >> ./$FILENAME.log 2>&1
echo "양호 : login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정 이 적용된 경우" >> ./$FILENAME.log 2>&1
echo "1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우" >> ./$FILENAME.log 2>&1
echo "2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우" >> ./$FILENAME.log 2>&1
echo "3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 ‘+’ 설정이 없는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : login, shell, exec 서비스를 사용하고, 위와 같은 설정이 적용되지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-17 start"											>> ./$FILENAME.log 2>&1
echo "[ Case 1 : hosts.equiv : permission check ]"							>> ./$FILENAME.log 2>&1
	ls -al $HOSTS_EQUIV										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 1 : hosts.equiv : configuration check ]"							>> ./$FILENAME.log 2>&1
	(cat $HOSTS_EQUIV | grep -v "#") 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ /.rhosts : check configuration ]"								>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
	FILES=".rhosts"
	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    FILE=$dir/$file
	    if [ -f $FILE ]
	      then
			echo "- $FILE"									>> ./$FILENAME.log 2>&1
			echo "[ Case 2 : .rhosts : permission check ]"					>> ./$FILENAME.log 2>&1
			ls -al $FILE									>> ./$FILENAME.log 2>&1
			echo "+++++" 									>> ./$FILENAME.log 2>&1
			echo " " 									>> ./$FILENAME.log 2>&1
			echo "[ Case 2 : .rhosts : configuration check ]"				>> ./$FILENAME.log 2>&1
			(cat $FILE)									>> ./$FILENAME.log 2>&1
			echo "+++++" 									>> ./$FILENAME.log 2>&1
			echo " " 									>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-17 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-18 접속 IP 및 포트 제한]">> ./$FILENAME.log 2>&1
echo "양호 : 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우">> ./$FILENAME.log 2>&1
echo "취약 : 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정하지 않은 경우">> ./$FILENAME.log 2>&1
echo "##### U-35 start"											>> ./$FILENAME.log 2>&1
echo "[ Check 1 : /etc/hosts.allow : permission check ]"						>> ./$FILENAME.log 2>&1
	ls -al /etc/hosts.allow										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check 1 : /etc/hosts.allow : content check ]"							>> ./$FILENAME.log 2>&1
	(cat /etc/hosts.allow || echo "[no config]")							>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check 2 : /etc/hosts.deny : permission check ]"							>> ./$FILENAME.log 2>&1
	ls -al /etc/hosts.deny										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check 2 : /etc/hosts.deny :  content check ]"							>> ./$FILENAME.log 2>&1
	(cat /etc/hosts.deny || echo "[no config]") 							>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	echo "[ Check 3 : /var/adm/inetd.sec : permission check ]"					>> ./$FILENAME.log 2>&1
		ls -al /var/adm/inetd.sec								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check 3 : /var/adm/inetd.sec : content check ]"						>> ./$FILENAME.log 2>&1
		(cat /var/adm/inetd.sec || echo "[no config]") 						>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[ Check 3 : /etc/sysconfig/iptables : permission check ]"					>> ./$FILENAME.log 2>&1
		ls -al /etc/sysconfig/iptables								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check 3 : /etc/sysconfig/iptables : content check ]"					>> ./$FILENAME.log 2>&1
		(cat /etc/sysconfig/iptables || echo "[no config]") 					>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-18 finish"										>> ./$FILENAME.log 2>&1
echo " "


echo "[U-19 Finger 서비스 비활성화]" >> ./$FILENAME.log 2>&1
echo "양호 : Finger 서비스가 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : Finger 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-19 start"											>> ./$FILENAME.log 2>&1
echo "[ Check 1 : Case 1 : /etc/inetd.conf : service check ]"			 			>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep finger || echo "Finger service : disable")				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check 1 : Case 2 : /etc/xinetd.d : service check]"			 			>> ./$FILENAME.log 2>&1
	(ls -al /etc/xinetd.d | grep finger)								>> ./$FILENAME.log 2>&1
	(cat /etc/xinetd.d/finger | egrep "service|disable" )						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check 2 : finger Process ]"			 						>> ./$FILENAME.log 2>&1
	(ps -ef | grep finger | grep -v grep || echo "Finger service : disable")			>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-19 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1



echo "[U-20 Anonymous FTP 비활성화]" >> ./$FILENAME.log 2>&1
echo "양호 : Anonymous FTP (익명 ftp) 접속을 차단한 경우" >> ./$FILENAME.log 2>&1
echo "취약 : Anonymous FTP (익명 ftp) 접속을 차단하지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-20 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	echo "[ Case 1 : Check 1 : FTP service  ]"							>> ./$FILENAME.log 2>&1
		svcs -p "*ftp*"										>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Case 1 : Check 1 : FTP service ]"			 				>> ./$FILENAME.log 2>&1
		(ps -ef | grep ftp | grep -v grep) 							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "[ Case 1 : Check 2 : FTP port ]"									>> ./$FILENAME.log 2>&1
	(netstat -an | grep :21 | grep LISTEN)								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 1 : Check 3 : FTP account ]"								>> ./$FILENAME.log 2>&1
	(cat $PASSWD | grep '^ftp' | grep -v grep) 							>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-20 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1


echo "[U-21 r 계열 서비스 비활성화] " >> ./$FILENAME.log 2>&1
echo "양호 : 불필요한 r 계열 서비스가 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 불필요한 r 계열 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-21 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[ Check point 1 : r command in /etc/inetd.conf ]" 						>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'rsh|rcp|rlogin|rexec' || echo "[ no r command ]")	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 2 : r command process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'rsh|rcp|rlogin|rexec' | grep -v grep || echo rsh,rcp,rlogin,rexec no process)	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 3 : Case 1 : /etc/hosts.equiv ]"							>> ./$FILENAME.log 2>&1
		(cat $HOSTS_EQUIV | grep -v '#') 								>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 3 : Case 2 : /.rhosts ]"								>> ./$FILENAME.log 2>&1
		HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
		FILES=".rhosts"

		for file in $FILES
		  do
		    FILE=$FILES
		    if [ -f $FILE ];
		      then
			ls -alL $FILE										>> ./$FILENAME.log 2>&1
		    fi
		  done

		for dir in $HOMEDIRS
		do
		  for file in $FILES
		  do
		    FILE=$dir/$file
		    if [ -f $FILE ];
		      then
				echo "- $FILE"									>> ./$FILENAME.log 2>&1
				cat $FILE									>> ./$FILENAME.log 2>&1
		    fi
		  done
		done
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[ Check point 1 : r command in /etc/inetd.conf ]" 						>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'rsh|rcp|rlogin|rexec')					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 2 : r command process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'rsh|rcp|rlogin|rexec' | grep -v grep || echo rsh,rcp,rlogin,rexec no process)	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 3 : Case 1 : /etc/hosts.equiv ]"							>> ./$FILENAME.log 2>&1
		cat $HOSTS_EQUIV 										>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 3 : Case 2 : /.rhosts ]"								>> ./$FILENAME.log 2>&1
		HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
		FILES=".rhosts"
		for dir in $HOMEDIRS
		do
		  for file in $FILES
		  do
		    FILE=$dir/$file
		    if [ -f $FILE ];
		      then
				echo "- $FILE"									>> ./$FILENAME.log 2>&1
				cat $FILE									>> ./$FILENAME.log 2>&1
		    fi
		  done
		done
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[ Check point 1 : Case 1 : r command in /etc/inetd.conf ]" 					>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'rsh|rcp|rlogin|rexec' || echo "[ no r commands ]")	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 1 : Case 2 : r command in /etc/xinetd.conf ]" 					>> ./$FILENAME.log 2>&1
		(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'rsh|rcp|rlogin|rexec' || echo "[ no r commands ]")>> ./$FILENAME.log 2>&1
		echo " " 											>> ./$FILENAME.log 2>&1
		(cat /etc/xinetd.d/rsh || echo "[ rsh service : disable ]")					>> ./$FILENAME.log 2>&1
		echo " " 											>> ./$FILENAME.log 2>&1
		(cat /etc/xinetd.d/rcp || echo "[ rcp service : disable ]")					>> ./$FILENAME.log 2>&1
		echo " " 											>> ./$FILENAME.log 2>&1
		(cat /etc/xinetd.d/rlogin || echo "[ rlogin service : disable ]")				>> ./$FILENAME.log 2>&1
		echo " " 											>> ./$FILENAME.log 2>&1
		(cat /etc/xinetd.d/rexec || echo "[ rexec service : disable ]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 2 : r command process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'rsh|rcp|rlogin|rexec' | grep -v grep || echo rsh,rcp,rlogin,rexec no process)	>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 3 : Case 1 : /etc/hosts.equiv ]"							>> ./$FILENAME.log 2>&1
		cat $HOSTS_EQUIV 										>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 3 : Case 2 : /.rhosts ]"								>> ./$FILENAME.log 2>&1
		HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
		FILES=".rhosts"

		for file in $FILES
		  do
		    FILE=$FILES
		    if [ -f $FILE ];
		      then
			ls -alL $FILE										>> ./$FILENAME.log 2>&1
		    fi
		  done

		for dir in $HOMEDIRS
		do
		  for file in $FILES
		  do
		    FILE=$dir/$file
		    if [ -f $FILE ];
		      then
				echo "- $FILE"									>> ./$FILENAME.log 2>&1
				cat $FILE									>> ./$FILENAME.log 2>&1
		    fi
		  done
		done
	echo "+++++" 												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "[ Check point 1 : Case 1 : r command ]" 								>> ./$FILENAME.log 2>&1
		(cat ./portlog.log | egrep 'rsh|rcp|rlogin|rexec' || echo "[ no r command ]")			>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 2 : Case 1 : /etc/hosts.equiv ]"							>> ./$FILENAME.log 2>&1
		(cat $HOSTS_EQUIV | grep -v '#') 								>> ./$FILENAME.log 2>&1
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
	echo "[ Check point 2 : Case 2 : /.rhosts ]"								>> ./$FILENAME.log 2>&1
		HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
		FILES=".rhosts"
		for dir in $HOMEDIRS
		do
		  for file in $FILES
		  do
		    FILE=$dir/$file
		    if [ -f $FILE ];
		      then
				echo "- $FILE"									>> ./$FILENAME.log 2>&1
				cat $FILE									>> ./$FILENAME.log 2>&1
		    fi
		  done
		done
	echo "+++++"												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
fi

echo "##### U-21 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1


echo "[U-22 crond 파일 소유자 및 권한 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : crontab 명령어 일반사용자 금지 및 cron 관련 파일 640 이하인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : crontab 명령어 일반사용자 사용가능하거나, crond 관련 파일 640 이상인 경우" >> ./$FILENAME.log 2>&1
echo "##### U-22 start"											>> ./$FILENAME.log 2>&1
	ls -al $CRON_ALLOW $CRON_DENY									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-22 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-23 DoS 공격에 취약한 서비스 비활성화]" >> ./$FILENAME.log 2>&1
echo "양호 : 사용하지 않는 DoS 공격에 취약한 서비스가 비활성화 된 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 사용하지 않는 DoS 공격에 취약한 서비스가 활성화 된 경우">> ./$FILENAME.log 2>&1
echo "##### U-23 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "Linux" ]; then
	echo "[ Check Point 1 : inetd.conf  ]"										>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'echo|discard|daytime|chargen' || echo "[ echo,discard,daytime,chargen service : disable ]")		>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : /etc/xinetd.d  ]"							>> ./$FILENAME.log 2>&1
		(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'echo|discard|daytime|chargen' || echo "[ echo,discard,daytime,chargen service : disable ]")	>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 3 : Process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'echo|discard|daytime|chargen' | grep -v grep || echo "[ echo,discard,daytime,chargen service : disable ]")			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "[ Check Point 1 : inetd.conf ]"								>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep -v '^#' | egrep 'echo|discard|daytime|chargen' || echo "[ echo,discard,daytime,chargen service : disable ]")																					>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : Process ]" 								>> ./$FILENAME.log 2>&1
		(cat ./portlog.log | egrep 'echo|discard|daytime|chargen' || echo "[ echo,discard,daytime,chargen service : disable ]")				>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check Point 1 : inetd.conf  ]"								>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'echo|discard|daytime|chargen' || echo "[ echo,discard,daytime,chargen service : disable ]")		>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : Process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'echo|discard|daytime|chargen' | grep -v grep || echo "[ echo,discard,daytime,chargen service : disable ]")			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
fi
echo "##### U-23 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-24 NFS 서비스 비활성화]" >> ./$FILENAME.log 2>&1
echo "양호 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 불필요한 NFS 서비스 관련 데몬이 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-24 start"									 		>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	echo "[ Check : NFS service ]"									>> ./$FILENAME.log 2>&1
		svcs -p "*nfs*"										>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check : NFS service ]"									>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'nfs|statd|lockd' | grep -v grep || echo "[ NFS service : disable ]" ) 	>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-24 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-25 NFS NFS 접근 통제]" >> ./$FILENAME.log 2>&1
echo "양호 : 불필요한 NFS 서비스를 사용하지 않거나, 불가피하게 사용 시 everyone 공유를 제한한 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 불필요한 NFS 서비스를 사용하고 있고, everyone 공유를 제한하지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-25 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[ Check Point 1 : /etc/exports : check permission ]"					>> ./$FILENAME.log 2>&1
		(ls -al $NFS_CONF)									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : /etc/exports : check configuration ]"					>> ./$FILENAME.log 2>&1
		(cat $NFS_CONF || echo "[ no config ]")							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 3 : share ] "								>> ./$FILENAME.log 2>&1
		share											>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[ Case 1 : Check Point 1 : /etc/exports : check permission ]"				>> ./$FILENAME.log 2>&1
		(ls -al $NFS_CONF)									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : Check Point 2 : /etc/exports : check configuration ]"				>> ./$FILENAME.log 2>&1
		(cat $NFS_CONF || echo "[ no config ]")							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 1 : Check Point 3 : share ] "							>> ./$FILENAME.log 2>&1
		share											>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Check Point 1 : /etc/dfs/dfstab : check permission ]"				>> ./$FILENAME.log 2>&1
		(ls -al /etc/dfs/dfstab)								>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Check Point 2 : /etc/dfs/dfstab : check configuration ]"			>> ./$FILENAME.log 2>&1
		(cat $NFS_CONF || echo "[ no config ]")							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Check Point 3 : share ] "							>> ./$FILENAME.log 2>&1
		share											>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[ Check Point 1 : /etc/exports : check permission ]"					>> ./$FILENAME.log 2>&1
		(ls -al $NFS_CONF)									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : /etc/exports : check configuration ]"					>> ./$FILENAME.log 2>&1
		(cat $NFS_CONF || echo "[ no config ]")							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 3 : share ] "								>> ./$FILENAME.log 2>&1
		share											>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "[ Check Point 1 : /etc/dfs/dfstab : check permission ]"					>> ./$FILENAME.log 2>&1
		(ls -al /etc/dfs/dfstab)								>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : /etc/dfs/dfstab : check configuration ]"				>> ./$FILENAME.log 2>&1
		(cat $NFS_CONF || echo "[ no config ]")							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 3 : share ] "								>> ./$FILENAME.log 2>&1
		share											>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-25 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-26 automountd 제거]" >> ./$FILENAME.log 2>&1
echo "양호 : automountd 서비스가 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : automountd 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-26 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	svcs -p "*autofs*"										>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	(ps -ef | grep automount)									>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1

fi
echo "##### U-26 finish"										>> ./$FILENAME.log 2>&1



echo "[U-27 RPC 서비스 확인]" >> ./$FILENAME.log 2>&1
echo "양호 : 불필요한 RPC 서비스가 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 불필요한 RPC 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-27 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	svcs -p "*rpc*"											>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check point 1 : Case 1 : $INETD_CONF ]" 						>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'rpc.cmsd|rusersd|rstatd|rpc.statd|kcms_server|rpc.ttdbserverd|Walld|rpc.nids|rpc.ypupdated|cachefsd|sadmind|sprayd|rpc.pcnfsd|rexd|rpc.rquotad')	>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	if [ $OS == "Linux" ]; then
		echo "[ Check point 1 : Case 2 : /etc/xinetd.d ]" 					>> ./$FILENAME.log 2>&1
			(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'rpc.cmsd|rusersd|rstatd|rpc.statd|kcms_server|rpc.ttdbserverd|Walld|rpc.nids|rpc.ypupdated|cachefsd|sadmind|sprayd|rpc.pcnfsd|rexd|rpc.rquotad')	>> ./$FILENAME.log 2>&1
		echo "+++++" 										>> ./$FILENAME.log 2>&1
		echo " " 										>> ./$FILENAME.log 2>&1
	fi
	echo "[ Check Point 2 : rpc Process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'rpc.cmsd|rusersd|rstatd|rpc.statd|kcms_server|rpc.ttdbserverd|Walld|rpc.nids|rpc.ypupdated|cachefsd|sadmind|sprayd|rpc.pcnfsd|rexd|rpc.rquotad' | grep -v grep) >> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-27 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-28 NIS, NIS+ 점검]" >> ./$FILENAME.log 2>&1
echo "양호 : NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : NIS 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-28 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	(cat ./portlog.log | egrep 'ypserv|ypbind|rpc.yppasswdd|ypxfrd|rpc.ypupdate' || echo "[ NIS service : disable ]")				>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	(ps -ef | grep -v 'grep' | egrep 'ypserv|ypbind|rpc.yppasswdd|ypxfrd|rpc.ypupdate' | grep -v grep || echo "[ NIS service : disable ]") 		>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
fi
echo "##### U-28 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-29 tftp, talk 서비스 비활성화]" >> ./$FILENAME.log 2>&1
echo "양호 : tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : tftp, talk, ntalk 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-29 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	echo "[ Check Point 1 : $INTED_CONF ]" 								>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'tftp|talk|ntalk' || echo "[ tftp, talk, ntalk service : disable ]")																					>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check Point 2 : Process ]" 								>> ./$FILENAME.log 2>&1
		(cat ./portlog.log | egrep 'tftp|talk|ntalk' || echo "[ tftp, talk, ntalk service : disable ]")						>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check point 1 : Case 1 : $INETD_CONF ]" 						>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF | grep -v '^#' | egrep 'tftp|talk|ntalk' || echo "[ tftp, talk, ntalk service : disable ]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	if [ $OS == "Linux" ]; then
		echo "[ Check point 1 : Case 2 : /etc/xinetd.d ]" 					>> ./$FILENAME.log 2>&1
			(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'tftp|talk|ntalk' || echo "[ tftp, talk, ntalk service : disable ]")		>> ./$FILENAME.log 2>&1
		echo "+++++" 										>> ./$FILENAME.log 2>&1
		echo " " 										>> ./$FILENAME.log 2>&1
	fi
	echo "[ Check Point 2 : Process ]" 								>> ./$FILENAME.log 2>&1
		(ps -ef | egrep 'tftp|talk' | grep -v grep || echo "[ tftp, talk, ntalk service : disable ]")						>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-29 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-30 Sendmail 버전 점검]" >> ./$FILENAME.log 2>&1
echo "양호 : Sendmail 버전이 최신버전인 경우" >> ./$FILENAME.log 2>&1
echo "취약 : Sendmail 버전이 최신버전이 아닌 경우" >> ./$FILENAME.log 2>&1
echo "##### U-30 start"											>> ./$FILENAME.log 2>&1
echo "[ Check Point 1 : SMTP service ]"			 						>> ./$FILENAME.log 2>&1
	(ps -ef | grep sendmail | grep -v grep) 							>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 2 : SMTP port ]"									>> ./$FILENAME.log 2>&1
	netstat -an | grep :25 | grep LISTEN 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 3 : Sendmail Package Version ]"							>> ./$FILENAME.log 2>&1
	(rpm -q sendmail --queryformat '%{name} %{version}\n') 						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 4 : Sendmail Version ]"								>> ./$FILENAME.log 2>&1
	(grep DZ $SMTP_CONF) 										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-30 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-31 스팸 메일 릴레이 제한]" >> ./$FILENAME.log 2>&1
echo "양호 : SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : SMTP 서비스를 사용하며 릴레이 제한이 설정되어 있지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-31 start"											>> ./$FILENAME.log 2>&1
echo "[ Check Point 1 : SPAM relay ]"									>> ./$FILENAME.log 2>&1
	cat /etc/mail/access										>> ./$FILENAME.log 2>&1
	cat /etc/mail/access.db										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 2 : sendmail.cf ]"									>> ./$FILENAME.log 2>&1
	(cat $SMTP_CONF | grep "R$\*" | grep "Relaying denied")						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-31 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-32 일반사용자의 Sendmail 실행 방지]" >> ./$FILENAME.log 2>&1
echo "양호 : SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정된 경우" >> ./$FILENAME.log 2>&1
echo "취약 : SMTP 서비스 사용 및 일반 사용자의 Sendmail 실행 방지가 설정되어 있지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-32 start"											>> ./$FILENAME.log 2>&1
	(cat $SMTP_CONF  | grep PrivacyOptions || echo "[ no config ]") 				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-32 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-33 DNS 보안 버전 패치]" >> ./$FILENAME.log 2>&1
echo "양호 : DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우 ">> ./$FILENAME.log 2>&1
echo "취약 : DNS 서비스를 사용하며 주기적으로 패치를 관리하고 있지 않는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-33 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[ Check Point 1 : DNS service ]"								>> ./$FILENAME.log 2>&1
		svcs -p "*named*"									>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check Point 1 : DNS service ]"								>> ./$FILENAME.log 2>&1
		(ps -ef | grep named | grep -v grep || echo "[ named daemon : disable ]")		>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi

echo "[ Check Point 2 : DNS port(53) ]"									>> ./$FILENAME.log 2>&1
	(netstat -an | grep :53 | grep LISTEN || echo "[ DNS port(53) : not opend ]") 			>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 3 : DNS version ]"									>> ./$FILENAME.log 2>&1
    dig @localhost txt chaos version.bind. 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-33 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-34 DNS Zone Transfer 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우" >> ./$FILENAME.log 2>&1
echo "취약 : DNS 서비스를 사용하며 Zone Transfer를 모든 사용자에게 허용한 경우" >> ./$FILENAME.log 2>&1
echo "##### U-51 start"											>> ./$FILENAME.log 2>&1
echo "[ Case 1 : DNS ZoneTransfer : allow-transfer in /etc/named.conf : BIND8]"				>> ./$FILENAME.log 2>&1
	(cat /etc/named.conf | grep allow-transfer || echo "[no configuration]")			>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 2 : DNS ZoneTransfer : xfrnets in /etc/named.boot : BIND4.9]"				>> ./$FILENAME.log 2>&1
	(cat /etc/named.boot | grep xfrnets || echo "[no configuration]")				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-51 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1



echo "[U-35 웹서비스 디렉토리 리스팅 제거]" >> ./$FILENAME.log 2>&1
echo "양호 : 디렉터리 검색 기능을 사용하지 않는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 디렉터리 검색 기능을 사용하는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-35 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		ret=`awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$' | grep -i indexes`
		if [ `awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$' | grep -i indexes | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Indexes is set"									>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v grep							>> ./$FILENAME.log 2>&1
		fi
		awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$'			>> ./$FILENAME.log 2>&1
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		ret=`awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$' | grep -i indexes`
		if [ `awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$' | grep -i indexes | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Indexes is set"									>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v grep							>> ./$FILENAME.log 2>&1
		fi
		awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$'			>> ./$FILENAME.log 2>&1
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-35 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1







echo "[U-36 웹서비스 웹 프로세스 권한 제한]" >> ./$FILENAME.log 2>&1
echo "양호 : Apache 데몬이 root 권한으로 구동되지 않는 경우">> ./$FILENAME.log 2>&1
echo "취약 : Apache 데몬이 root 권한으로 구동되는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-36 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `ps -ef | grep httpd | grep -v root | grep -v grep | wc -l` -ge 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v root | grep -v grep					>> ./$FILENAME.log 2>&1
		else
			echo "Apache is running as root"							>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v grep							>> ./$FILENAME.log 2>&1
		fi
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `ps -ef | grep httpd | grep -v root | grep -v grep | wc -l` -ge 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v root | grep -v grep					>> ./$FILENAME.log 2>&1
		else
			echo "Apache is running as root"							>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v grep							>> ./$FILENAME.log 2>&1
		fi
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-36finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1



echo "[U-37 웹서비스 디렉토리 리스팅 제거]"	>> ./$FILENAME.log 2>&1
echo "양호 : 상위 디렉터리에 이동제한을 설정한 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : 상위 디렉터리에 이동제한을 설정하지 않은 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-37 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i indexes | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "*** Allowed Directory Listing($HTTPD_CONF)"					>> ./$FILENAME.log 2>&1
			grep -n -i indexes $HTTPD_CONF | grep -v '#'						>> ./$FILENAME.log 2>&1
		fi
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i indexes | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "*** Allowed Directory Listing($HTTPD_CONF)"					>> ./$FILENAME.log 2>&1
			grep -n -i indexes $HTTPD_CONF | grep -v '#'						>> ./$FILENAME.log 2>&1
		fi
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-37 finish"											>> ./$FILENAME.log 2>&1
echo " "



echo "[U-38 웹서비스 불필요한 파일 제거]" >> ./$FILENAME.log 2>&1
echo "양호 : 기본으로 생성되는 불필요한 파일 및 디렉터리가 제거되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 기본으로 생성되는 불필요한 파일 및 디렉터리가 제거되지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-38 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `ls -ald $HTTPD_ROOT | egrep -i 'samples|docs' | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			echo `ls -ald $HTTPD_ROOT`								>> ./$FILENAME.log 2>&1
			ls -al $HTTPD_ROOT									>> ./$FILENAME.log 2>&1
		else
			echo "Unnecessary file exists"								>> ./$FILENAME.log 2>&1
			ls -al $HTTPD_ROOT | egrep -i 'samples|docs'						>> ./$FILENAME.log 2>&1
		fi
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `ls -ald $HTTPD_ROOT | egrep -i 'samples|docs' | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			echo `ls -ald $HTTPD_ROOT`								>> ./$FILENAME.log 2>&1
			ls -al $HTTPD_ROOT									>> ./$FILENAME.log 2>&1
		else
			echo "Unnecessary file exists"								>> ./$FILENAME.log 2>&1
			ls -al $HTTPD_ROOT | egrep -i 'samples|docs'						>> ./$FILENAME.log 2>&1
		fi
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-38 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "[U-39 웹서비스 링크 사용금지]" >> ./$FILENAME.log 2>&1
echo "양호 : 심볼릭 링크, aliases 사용을 제한한 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 심볼릭 링크, aliases 사용을 제한하지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-39 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i followsymlinks | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Allowed Symbolic link($HTTPD_CONF)"						>> ./$FILENAME.log 2>&1
			grep -n -i followsymlinks $HTTPD_CONF | grep -v '#'					>> ./$FILENAME.log 2>&1
		fi
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i followsymlinks | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Allowed Symbolic link($HTTPD_CONF)"						>> ./$FILENAME.log 2>&1
			grep -n -i followsymlinks $HTTPD_CONF | grep -v '#'					>> ./$FILENAME.log 2>&1
		fi
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-39 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "[U-40 웹서비스 파일 업로드 및 다운로드 제한]" >> ./$FILENAME.log 2>&1
echo "양호 : 파일 업로드 및 다운로드를 제한한 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 파일 업로드 및 다운로드를 제한하지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-40 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i limitrequestbody | wc -l` -ge 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			grep -n -i limitrequestbody $HTTPD_CONF | grep -v '#'					>> ./$FILENAME.log 2>&1
		else
			echo "No limit capacity to upload and download"						>> ./$FILENAME.log 2>&1
		fi
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i limitrequestbody | wc -l` -ge 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			grep -n -i limitrequestbody $HTTPD_CONF | grep -v '#'					>> ./$FILENAME.log 2>&1
		else
			echo "No limit capacity to upload and download"						>> ./$FILENAME.log 2>&1
		fi
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-40 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1



echo "[U-41 웹서비스 영역의 분리]" >> ./$FILENAME.log 2>&1
echo "양호 : DocumentRoot를 별도의 디렉터리로 지정한 경우" >> ./$FILENAME.log 2>&1
echo "취약 : DocumentRoot를 기본 디렉터리로 지정한 경우" >> ./$FILENAME.log 2>&1
echo "##### U-41 start"												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		grep -i "^documentroot" $HTTPD_CONF | awk '{print$2}' | tr -d \" > u-41.txt

		if [ `cat u-41.txt | grep '$HTTPD_ROOT' | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			rm -rf u-41.txt
		else
			echo "DocumentRoot exists in the installation directory of Apache."			>> ./$FILENAME.log 2>&1
			rm -rf u-41.txt
		fi
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		grep -i "^documentroot" $HTTPD_CONF | awk '{print$2}' | tr -d \" > u-41.txt

		if [ `cat u-41.txt | grep '$HTTPD_ROOT' | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			rm -rf u-41.txt
		else
			echo "DocumentRoot exists in the installation directory of Apache."			>> ./$FILENAME.log 2>&1
			rm -rf u-41.txt
		fi
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-41 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1





echo "[U-42 최신 보안패치 및 벤더 권고사항 적용]" >> ./$FILENAME.log 2>&1
echo "양호 : 패치 적용 정책을 수립하여 주기적으로 패치관리를 하고 있으며, 패치 관련 내용을 확인하고 적용했을 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 패치 적용 정책을 수립하지 않고 주기적으로 패치관리를 하지 않거나 패 치 관련 내용을 확인하지 않고 적용하지 않았을 경우" >> ./$FILENAME.log 2>&1
echo "##### U-42 start"											>> ./$FILENAME.log 2>&1
echo "Manual Check by Interview"									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-42 finish"										>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1

echo "[U-43 로그의 정기적 검토 및 보고]" >> ./$FILENAME.log 2>&1
echo "양호 : 접속기록 등의 보안 로그, 응용 프로그램 및 시스템 로그 기록에 대해 정기 적으로 검토, 분석, 리포트 작성 및 보고 등의 조치가 이루어지는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 위 로그 기록에 대해 정기적으로 검토, 분석, 리포트 작성 및 보고 등의 조 치가 이루어 지지 않는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-43 start"											>> ./$FILENAME.log 2>&1
echo "Manual Check by Interview"									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-43 finish"										>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1




echo "[U-44 root 이외의 UID가 ‘0’ 금지]" >> ./$FILENAME.log 2>&1
echo "양호 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : root 계정과 동일한 UID를 갖는 계정이 존재하는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-44 start"											>> ./$FILENAME.log 2>&1
echo "[ root UID '0' ]"											>> ./$FILENAME.log 2>&1
	awk -F: '$3==0 { print $1 " -> UID=" $3 }' $PASSWD | grep -v root				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ $PASSWD ]"											>> ./$FILENAME.log 2>&1
	awk -F: '{print $1, $3}' $PASSWD 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-44 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1


echo "[U-45 root 계정 su 제한]" >> ./$FILENAME.log 2>&1
echo "양호 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있는 경우 ※ 일반사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용제한 불필요" >> ./$FILENAME.log 2>&1
echo "취약 : su 명령어를 모든 사용자가 사용하도록 설정되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-45 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "Linux" ]; then
	echo "[ Case 1 - /bin/su permission ]"								>> ./$FILENAME.log 2>&1
		ls -al /bin/su										>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 1 - /bin/su group ]"								>> ./$FILENAME.log 2>&1
		DIRS=`ls -al /etc/pam.d/su| awk '{print $4}'`
		 for dir in $DIRS
		  do
		    (cat /etc/group | grep $dir:)							>> ./$FILENAME.log 2>&1
		    echo "+++++" 									>> ./$FILENAME.log 2>&1
		    echo " " 										>> ./$FILENAME.log 2>&1
		 done
	echo "[ Case 2 : Using Pam Module - /etc/pam.d/su permission ]"					>> ./$FILENAME.log 2>&1
		ls -al /etc/pam.d/su									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Case 2 : Using Pam Module - wheel group ]"				 		>> ./$FILENAME.log 2>&1
		(cat /etc/group | grep wheel)								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[  Case 2 : Using Pam Module - /etc/pam.d/su config ]"					>> ./$FILENAME.log 2>&1
		(cat /etc/pam.d/su | grep pam_*)							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ /usr/bin/su properties ]"								>> ./$FILENAME.log 2>&1
	ls -al /usr/bin/su										>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	echo "[ Check su group ]"				 					>> ./$FILENAME.log 2>&1
	DIRS=`ls -al /usr/bin/su| awk '{print $4}'`
         for dir in $DIRS
          do
	    (cat $GROUP | grep $dir:)									>> ./$FILENAME.log 2>&1
         done
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
fi
echo "##### U-45 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-46 패스워드 최소 길이 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : 패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 패스워드 최소 길이가 8자 미만으로 설정되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-46 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	egrep -i ":$|minlen" $PASSWD_CONF								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[Standard Mode & Trusted Mode] " 								>> ./$FILENAME.log 2>&1
	egrep -i ":$|MIN_PASSWORD_LENGTH" $PASSWD_CONF							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	(cat $PASSWD_CONF | grep -i MIN_PASSWORD_LENGTH || echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	(cat $PASSWD_CONF | grep -i PASSLENGTH)								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	(cat $PASSWD_CONF | grep -i PASS_MIN_LEN)							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	(cat $PASSWD_CONF | grep -i PASSLENGTH=	|| echo "[no config]")					>> ./$FILENAME.log 2>&1
echo "+++++"												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
fi
echo "##### U-46 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-47 패스워드 최대 사용기간 설정]"	>> ./$FILENAME.log 2>&1
echo "양호 : 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있는 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있지 않는 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-47 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	egrep -i ":$|maxage" $PASSWD_CONF								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[Standard Mode] " 									>> ./$FILENAME.log 2>&1
	(cat $PASSWD_CONF | grep -i PASSWORD_MAXDAYS	|| echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
echo "[Trusted Mode] " 											>> ./$FILENAME.log 2>&1
	(cat $PASSWD_CONF_TR | egrep -i 'u_exp' || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	(cat $PASSWD_CONF | grep -i MAXWEEKS) 								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	(cat $PASSWD_CONF | grep -i PASS_MAX_DAYS)  							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	(cat $PASSWD_CONF | grep -i MAXWEEKS= || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-47 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-48 패스워드 최소 사용기간 설정]"	>> ./$FILENAME.log 2>&1
echo "양호 : 패스워드 최소 사용기간이 1일 이상 설정되어 있는 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : 패스워드 최소 사용기간이 설정되어 있지 않는 경우" 	>> ./$FILENAME.log 2>&1

echo "##### U-48 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	egrep -i ":$|minage" $PASSWD_CONF								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	(cat $PASSWD_CONF | grep -i PASSWORD_MINDAYS	|| echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	(cat $PASSWD_CONF | grep -i PASS_MIN_DAYS)							>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	(cat $PASSWD_CONF | grep -i MINWEEKS	|| echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
fi
echo "##### U-48 finish"											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-49 불필요한 계정 제거]" >> ./$FILENAME.log 2>&1
echo "양호 : 불필요한 계정이 존재하지 않는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 불필요한 계정이 존재하는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-49 start"											>> ./$FILENAME.log 2>&1
echo "[ /etc/passwd ]"											>> ./$FILENAME.log 2>&1
	(cat $PASSWD | grep -v 'nologin' | grep -v 'false') 				 		>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ /etc/shadow ]"											>> ./$FILENAME.log 2>&1
	(cat $SHADOW)						 					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	usrck -n ALL											>> ./usrck.log 2>&1
	grep "locked" usrck.log										>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
	rm -rf usrck.log
fi
echo "##### U-49 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-50 관리자 그룹에 최소한의 계정 포함]" >> ./$FILENAME.log 2>&1
echo "양호 : 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 관리자 그룹에 불필요한 계정이 등록되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-50 start"											>> ./$FILENAME.log 2>&1
	(cat $GROUP | grep root)									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-50 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-51 계정이 존재하지 않는 GID 금지]" >> ./$FILENAME.log 2>&1
echo "양호 : 시스템 관리나 운용에 불필요한 그룹이 삭제 되어있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 시스템 관리나 운용에 불필요한 그룹이 존재할 경우" >> ./$FILENAME.log 2>&1
echo "##### U-51 start"											>> ./$FILENAME.log 2>&1
	awk -F: '$4==null' $GROUP									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-51 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-52 동일한 UID 금지]"  >> ./$FILENAME.log 2>&1
echo "양호 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"  >> ./$FILENAME.log 2>&1
echo "취약 : 동일한 UID로 설정된 사용자 계정이 존재하는 경우"  >> ./$FILENAME.log 2>&1
echo "##### U-52 start"											>> ./$FILENAME.log 2>&1
	ret=`awk -F: '{ print $3}' $PASSWD | sort | uniq -d | wc -l`
	if [ $ret -eq 0 ]; then
		echo "no same UID"									>> ./$FILENAME.log 2>&1
		echo " " 										>> ./$FILENAME.log 2>&1
		echo "UID : USERNAME"									>> ./$FILENAME.log 2>&1
		awk -F: '{ print $3 ":" $1 }' $PASSWD | sort						>> ./$FILENAME.log 2>&1
	else
		echo "exist same UID"									>> ./$FILENAME.log 2>&1
		ret2=`awk -F: '{ print $3 }' $PASSWD | sort | uniq -d`

		for RPM in $ret2; do
			awk -F: '$3=='$RPM' { print $0 }' $PASSWD					>> ./$FILENAME.log 2>&1
		done
	fi
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-52 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-53 사용자 shell 점검]" >> ./$FILENAME.log 2>&1
echo "양호 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : 로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되지 않은 경우" >> ./$FILENAME.log 2>&1
echo "##### U-53 start"											>> ./$FILENAME.log 2>&1
	(cat $PASSWD | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin")	>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-53 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-54 Session timeout 설정]" 	>> ./$FILENAME.log 2>&1
echo "양호 : Session Timeout이 600초(10분) 이하로 설정되어 있는 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : Session Timeout이 600초(10분) 이하로 설정되지 않은 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-54 start"											>> ./$FILENAME.log 2>&1
echo "[ Case 1 Check Point 1 : sh, ksh, bash TMOUT setting in /etc/profile ]"				>> ./$FILENAME.log 2>&1
	(cat $PROFILE | grep -i TMOUT || echo "[no config]")						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 2 : csh TMOUT setting in /etc/csh.login ]"							>> ./$FILENAME.log 2>&1
	(cat /etc/csh.login | grep -i autologout || echo "[no config]")					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	echo "[ Case 1 : Check Point 2 : $LOGIN_CONF ]"							>> ./$FILENAME.log 2>&1
	(cat $LOGIN_CONF | grep -i TIMEOUT || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-54 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1


echo "[U-55 hosts.lpd 파일 소유자 및 권한 설정]"		>> ./$FILENAME.log 2>&1
echo "양호 : hosts.lpd 파일이 삭제되어 있거나 불가피하게 hosts.lpd 파일을 사용할 시 파일의 소유자가 root이고 권한이 600인 경우"		>> ./$FILENAME.log 2>&1
echo "취약 : hosts.lpd 파일이 삭제되어 있지 않거나 파일의 소유자가 root가 아니고 권한이 600이 아닌 경우"		>> ./$FILENAME.log 2>&1
echo "##### U-55 start"											>> ./$FILENAME.log 2>&1
	ls -al $LPD 						 					>> ./$FILENAME.log 2>&1
echo "+++++"												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-55 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-56 UMASK 설정 관리]"		>> ./$FILENAME.log 2>&1
echo "양호 : UMASK 값이 022 이상으로 설정된 경우" 		>> ./$FILENAME.log 2>&1
echo "취약 : UMASK 값이 022 이상으로 설정되지 않은 경우" 		>> ./$FILENAME.log 2>&1
echo "##### U-56 start"											>> ./$FILENAME.log 2>&1
echo "[ Case 1 : umask command ]"									>> ./$FILENAME.log 2>&1
	umask												>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "[ Case 2 : umask in /etc/profile ]" 								>> ./$FILENAME.log 2>&1
	(cat $PROFILE | grep -i umask || echo "[no config]") 						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[ Case 3 : umask in /etc/security/user ]"	 						>> ./$FILENAME.log 2>&1
		(egrep ":$|umask" $PASSWD_CONF)								>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "[ Case 3 : umask in /etc/default/login ]"	 						>> ./$FILENAME.log 2>&1
		(cat /etc/default/login | grep -i umask || echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[ Case 3 : umask in /etc/default/login ]"	 						>> ./$FILENAME.log 2>&1
	    ls -al $LOGIN_CONF 										>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF | grep -i umask	|| echo "[no config]")				>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "[ Case 3 : umask in /etc/default/login ]"	 						>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF | grep -i umask || echo "[no config]")					>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "##### U-56 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-57 홈디렉토리 소유자 및 권한 설정]"		>> ./$FILENAME.log 2>&1
echo "양호 : 홈 디렉터리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우" 		>> ./$FILENAME.log 2>&1
echo "취약 : 홈 디렉터리 소유자가 해당 계정이 아니고, 타 사용자 쓰기 권한이 부여된 경우" 		>> ./$FILENAME.log 2>&1
echo "##### U-57 start"											>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: 'length($6) > 0 {print $6}' | sort -u`

         for dir in $HOMEDIRS
          do
            ls -dal $dir 										>> ./$FILENAME.log 2>&1
         done
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-57 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-58 홈디렉토리로 지정한 디렉토리의 존재 관리]" 	>> ./$FILENAME.log 2>&1
echo "양호 : 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : 홈 디렉터리가 존재하지 않는 계정이 발견된 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-58 start"											>> ./$FILENAME.log 2>&1
cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: 'length($6) > 0 {print $1, $6}' >> ./$FILENAME.log 2>&1

echo "##### U-58 finish"												>> ./$FILENAME.log 2>&1
echo " " 														>> ./$FILENAME.log 2>&1


echo "[U-59 숨겨진 파일 및 디렉토리 검색 및 제거]" 	>> ./$FILENAME.log 2>&1
echo "양호 : 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리를 삭제한 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : 불필요하거나 의심스러운 숨겨진 파일 및 디렉터리를 방치한 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-59 start"													>> ./$FILENAME.log 2>&1
echo "[ Case 1 ] "													>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: 'length($6) > 0 {print $6}' | sort -u`

         for dir in $HOMEDIRS
          do
	    echo "----------<" ${dir} ">----------"							>> ./$FILENAME.log 2>&1
	  		 ls -a $dir | grep "^\."							>> ./$FILENAME.log 2>&1
         done
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "[ Case 2 ] "											>> ./$FILENAME.log 2>&1
	find / -xdev -iname ".*" -type f -perm -1 -exec ls -al {} \;					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-59 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1




echo "[U-60 ssh 원격접속 허용]" 	>> ./$FILENAME.log 2>&1
echo "양호 : 원격 접속 시 SSH 프로토콜을 사용하는 경우" 	>> ./$FILENAME.log 2>&1
echo "※ ssh, telnet이 동시에 설치되어 있는 경우 취약한 것으로 평가됨"	>> ./$FILENAME.log 2>&1
echo "취약 : 원격 접속 시 Telnet, FTP 등 안전하지 않은 프로토콜을 사용하는 경우"	>> ./$FILENAME.log 2>&1
echo "##### U-60 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOs" ]; then
	echo "[ Check Point 1 : SSH service ]"								>> ./$FILENAME.log 2>&1
		svcs -p "*ssh*"										>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check Point 1 : SSH service ]"								>> ./$FILENAME.log 2>&1
		(ps -ef | grep ssh	| grep -v grep || echo "[ ssh service : disable ]")		>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "[ Check Point 2 : SSH port ]"				 					>> ./$FILENAME.log 2>&1
	netstat -an | grep :22 | grep LISTEN 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-60 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-61 ftp 서비스 확인]" >> ./$FILENAME.log 2>&1
echo "양호 : FTP 서비스가 비활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "취약 : FTP 서비스가 활성화 되어 있는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-61 start"											>> ./$FILENAME.log 2>&1
echo "[ Check Point 1 : Case 1 : FTP service in /etc/inetd.conf ]"			 		>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep -i ftp || echo "[ FTP service : disable ]")				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
if [ $OS == "Linux" ]; then
	echo "[ Check Point 1 : Case 2 : FTP service in /etc/xinetd.conf ]"			 	>> ./$FILENAME.log 2>&1
		(cat $XINETD_CONF | grep -i ftp || echo "[ FTP service : disable ]")			>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "[ Check Point 2 : FTP process ]"			 						>> ./$FILENAME.log 2>&1
	(ps -ef | grep ftp | grep -v grep || echo "[ FTP service : disable ]")				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 3 : FTP port ]"									>> ./$FILENAME.log 2>&1
	(netstat -an | grep *.21 | grep LISTEN || echo "[ FTP port : not opened ]")			>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-61 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-62 ftp 계정 shell 제한]" 	>> ./$FILENAME.log 2>&1
echo "양호 : ftp 계정에 /bin/false 쉘이 부여되어 있는 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : ftp 계정에 /bin/false 쉘이 부여되어 있지 않은 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-62 start"											>> ./$FILENAME.log 2>&1
	(cat $PASSWD | grep '^ftp' | grep -v grep || echo "[Do not exist!]")				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-62 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-63 ftpusers 파일 소유자 및 권한 설정]" 	>> ./$FILENAME.log 2>&1
echo "양호 : ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우" 	>> ./$FILENAME.log 2>&1
echo "취약 : ftpusers 파일의 소유자가 root가 아니거나, 권한이 640 이하가 아닌 경우" 	>> ./$FILENAME.log 2>&1
echo "##### U-63 start"											>> ./$FILENAME.log 2>&1
echo "[ PROFTP ]"											>> ./$FILENAME.log 2>&1
echo "[ /etc/ftpusers ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/ftpusers										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ NCFTP ]	"											>> ./$FILENAME.log 2>&1
echo "[ /etc/ftpd/ftpusers ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/ftpd/ftpusers									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ VSFTP ]	"											>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd.userlist]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd.userlist									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/user_list ]"									>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/user_list									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/vsftpd.userlist ]"									>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/vsftpd.userlist								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/ftpusers ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/ftpusers 									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/vsftpd.ftpusers ]"									>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/vsftpd.ftpusers 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-63 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-64 ftpusers 파일 설정(FTP 서비스 root 계정 접근제한)]"	>> ./$FILENAME.log 2>&1
echo "양호 : FTP 서비스가 비활성화 되어 있거나, 활성화 시 root 계정 접속을 차단 한 경우"	>> ./$FILENAME.log 2>&1
echo "취약 : FTP 서비스가 활성화 되어 있고, root 계정 접속을 허용한 경우"	>> ./$FILENAME.log 2>&1
echo "##### U-64 start"											>> ./$FILENAME.log 2>&1
echo "[ PROFTP ]	"										>> ./$FILENAME.log 2>&1
echo "[ content of /etc/ftpusers ]"									>> ./$FILENAME.log 2>&1
	(cat /etc/ftpusers)										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ NCFTP ]	"											>> ./$FILENAME.log 2>&1
echo "[ content of /etc/ftpd/ftpusers ]"								>> ./$FILENAME.log 2>&1
	(cat /etc/ftpd/ftpusers)									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ VSFTP ]	"											>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd.conf ]"									>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd.conf | grep userlist_enable || echo "[ no config ]")				>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/vsftpd.conf ]"								>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd/vsftpd.conf | grep userlist_enable || echo "[ no config ]")			>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd.userlist ]"								>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd.userlist)									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/user_list ]"								>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd/user_list)									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/vsftpd.userlist ]"							>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd/vsftpd.userlist)								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/ftpusers ]"								>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd/ftpusers) 									>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/vsftpd.ftpusers ]"							>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd/vsftpd.ftpusers) 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-64 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-65 at 서비스 권한 설정]"				>> ./$FILENAME.log 2>&1
echo "양호 : at 명령어 일반사용자 금지 및 at 관련 파일 640 이하인 경우"				>> ./$FILENAME.log 2>&1
echo "취약 : at 명령어 일반사용자 사용가능하거나, at 관련 파일 640 이상인 경우"				>> ./$FILENAME.log 2>&1
echo "##### U-65 start"											>> ./$FILENAME.log 2>&1
echo "[ Permission check : /etc/at.deny ]"								>> ./$FILENAME.log 2>&1
	ls -al $AT_DENY											>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Permission check : /etc/at.allow ]"								>> ./$FILENAME.log 2>&1
	ls -al $AT_ALLOW										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-65 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-66 SNMP 서비스 구동 점검]"		>> ./$FILENAME.log 2>&1
echo "양호 : SNMP 서비스를 사용하지 않는 경우" 		>> ./$FILENAME.log 2>&1
echo "취약 : SNMP 서비스를 사용하는 경우" 		>> ./$FILENAME.log 2>&1
echo "##### U-65 start"											>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	echo "[ Check Point 1 : SNMP service ]"			 					>> ./$FILENAME.log 2>&1
		svcs -p "*snmp*"									>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
else
	echo "[ Check Point 1 : SNMP service ]"			 					>> ./$FILENAME.log 2>&1
		(ps -ef | grep snmpd | grep -v grep || echo "[ SNMP service : disable ]") 		>> ./$FILENAME.log 2>&1
	echo "+++++"											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
fi
echo "[ Check Point 2 : SNMP port ]"									>> ./$FILENAME.log 2>&1
	(netstat -an | grep :161 || echo "[ SNMP port : not opened ]")					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-66 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-67 SNMP 서비스 Community String의 복잡성 설정]" >> ./$FILENAME.log 2>&1
echo "양호 : SNMP Community 이름이 public, private 이 아닌 경우" >> ./$FILENAME.log 2>&1
echo "취약 : SNMP Community 이름이 public, private 인 경우" >> ./$FILENAME.log 2>&1
echo "##### U-67 start"											>> ./$FILENAME.log 2>&1
echo "[ Check Point 1 : $SNMP_CONF permission ]"							>> ./$FILENAME.log 2>&1
	ls -al $SNMP_CONF										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "[ Check Point 2 : community string : $SNMP_CONF ]"						>> ./$FILENAME.log 2>&1
	(cat $SNMP_CONF  | grep community | grep -v '^#' || echo "[ no config ]") 			>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
if [ $OS == "AIX" ]; then
	echo "[ Check Point 3 : community string : snmpdv3 ]"						>> ./$FILENAME.log 2>&1
		(cat /etc/snmpdv3.conf  | grep -i community | grep -v '^#' || echo "[ no config ]")	>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
fi
echo "##### U-67 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-68 로그온 시 경고 메시지 제공]"		>> ./$FILENAME.log 2>&1
echo "양호 : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 메시지가 설정되어 있는 경우"		>> ./$FILENAME.log 2>&1
echo "취약 : 서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 메시지가 설정되어 있지 않은 경우"		>> ./$FILENAME.log 2>&1
echo "##### U-68 start"											>> ./$FILENAME.log 2>&1
echo "[ Case 1 : Common ssh & telnet banner : motd ]"							>> ./$FILENAME.log 2>&1
	(cat /etc/motd)											>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 2 : ssh banner : $SSH_CONF ]"								>> ./$FILENAME.log 2>&1
	(cat $SSH_CONF | grep -i Banner || echo "no configs")						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 3 : telnet banner : &TELNET_BANNER ]"							>> ./$FILENAME.log 2>&1
	(cat $TELNET_BANNER)										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 4 : FTP banner : $FTP_BANNER ]"								>> ./$FILENAME.log 2>&1
	(cat $FTP_BANNER | grep -i BANNER) 								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 4 : FTP banner : /etc/ftpd/ftpaccess(banner) ]"						>> ./$FILENAME.log 2>&1
	(`cat /etc/ftpd/ftpaccess | grep banner | awk '{print $2}'`)					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 4 : FTP banner : /etc/ftpd/ftpaccess(message) ]"						>> ./$FILENAME.log 2>&1
	(`cat /etc/ftpd/ftpaccess | grep message | awk '{print $2}'`)					>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Case 4 : FTP banner : /etc/ftpd/ftpaccess(version) ]"						>> ./$FILENAME.log 2>&1
	(cat /etc/ftpd/ftpaccess | grep greeting)							>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-68 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-69 NFS 설정파일 접근권한]"			>> ./$FILENAME.log 2>&1
echo "양호 : NFS 접근제어 설정파일의 소유자가 root 이고, 권한이 644 이하인 경우"			>> ./$FILENAME.log 2>&1
echo "취약 : NFS 접근제어 설정파일의 소유자가 root 가 아니거나, 권한이 644 이하 가 아닌 경우"			>> ./$FILENAME.log 2>&1
echo "##### U-69 start"											>> ./$FILENAME.log 2>&1
	ls -al $NFS_CONF										>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1
echo "##### U-69 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "[U-70 SMTP : expn, vrfy 명령어 제한]" >> ./$FILENAME.log 2>&1
echo "양호 : SMTP 서비스 미사용 또는, noexpn, novrfy 옵션이 설정되어 있는 경우">> ./$FILENAME.log 2>&1
echo "취약 : SMTP 서비스를 사용하고, noexpn, novrfy 옵션이 설정되어 있지 않는 경우" >> ./$FILENAME.log 2>&1
echo "##### U-70 start"											>> ./$FILENAME.log 2>&1
echo "[ Check Point 1 : Sendmail start script ]"							>> ./$FILENAME.log 2>&1
	(ls -al /sbin/rc*.d/* | grep -i sendmail | grep "/S")						>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "[ Check Point 2 : /etc/mail/sendmail.cf ]"							>> ./$FILENAME.log 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions						>> ./$FILENAME.log 2>&1
  else
    echo "[ no file(/etc/mail/sendmail.cf) ]"								>> ./$FILENAME.log 2>&1
fi
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo "##### U-70 finish"										>> ./$FILENAME.log 2>&1
echo " "												>> ./$FILENAME.log 2>&1

echo "[U-71 Apache 웹 서비스 정보 숨김]"	>> ./$FILENAME.log 2>&1
echo "양호 : ServerTokens Prod, ServerSignature Off로 설정되어있는 경우"	>> ./$FILENAME.log 2>&1
echo "취약 : ServerTokens Prod, ServerSignature Off로 설정되어있지 않은 경우"	>> ./$FILENAME.log 2>&1
echo "##### U-71 start"											>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	if [ $APACHE_CHECK = "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		check=`grep -i servertokens $HTTPD_CONF | awk '{print $2}' | grep "Prod" | wc -l`
		if [ `grep -i servertokens $HTTPD_CONF | awk '{print $2}' | grep "Prod" | wc -l` -eq 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Apache Web server ServerTokens has not been set"					>> ./$FILENAME.log 2>&1
		fi
		cat $HTTPD_CONF | grep -i servertokens								>> ./$FILENAME.log 2>&1
	fi
else
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		check=`grep -i servertokens $HTTPD_CONF | awk '{print $2}' | grep "Prod" | wc -l`
		if [ `grep -i servertokens $HTTPD_CONF | awk '{print $2}' | grep "Prod" | wc -l` -eq 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Apache Web server ServerTokens has not been set"					>> ./$FILENAME.log 2>&1
		fi
		cat $HTTPD_CONF | grep -i servertokens								>> ./$FILENAME.log 2>&1
	fi
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-71 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1



echo "[U-72 정책에 따른 시스템 로깅 설정]">> ./$FILENAME.log 2>&1
echo "양호 : 로그 기록 정책이 정책에 따라 설정되어 수립되어 있으며 보안정책에 따 라 로그를 남기고 있을 경우">> ./$FILENAME.log 2>&1
echo "취약 : 로그 기록 정책 미수립 또는, 정책에 따라 설정되어 있지 않거나 보안정 책에 따라 로그를 남기고 있지 않을 경우">> ./$FILENAME.log 2>&1
echo "##### U-72a start"											>> ./$FILENAME.log 2>&1
echo "[ Check Point 1 : $SYSLOG_CONF ]"									>> ./$FILENAME.log 2>&1
	(cat $SYSLOG_CONF | grep -v "#"	)								>> ./$FILENAME.log 2>&1
echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
if [ $OS = "HP-UX" ]; then
	echo "[ Check Point 2 : /var/adm/sulog  ]"							>> ./$FILENAME.log 2>&1
		tail -5 /var/adm/sulog									>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "[ Check Point 2 : /etc/rsyslog.conf  ]"							>> ./$FILENAME.log 2>&1
		(cat /etc/rsyslog.conf | grep -v "#"	)						>> ./$FILENAME.log 2>&1
	echo "+++++" 											>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
fi
echo "##### U-72 finish"										>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1



echo "Optional Check"
echo "============================ ETC ============================"					>> ./$FILENAME.log 2>&1
echo "========== Process "										>> ./$FILENAME.log 2>&1
if [ $OS == "SunOS" ]; then
	(svcs -pa | sort | uniq) 									>> ./$FILENAME.log 2>&1
else
	(ps -ef | grep -v grep | grep -v ps | sort | uniq)						>> ./$FILENAME.log 2>&1
fi
echo " " 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "========== Listen Port "										>> ./$FILENAME.log 2>&1
	netstat -an											>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "========== Password check "									>> ./$FILENAME.log 2>&1
echo "[ $SHADOW ]"											>> ./$FILENAME.log 2>&1
	awk -F: '{print $1":"$2}' $SHADOW 								>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1
echo " " 												>> ./$FILENAME.log 2>&1

echo "========== Pwquility check "									>> ./$FILENAME.log 2>&1
echo "[ $SHADOW ]"											>> ./$FILENAME.log 2>&1
    cat /etc/security/pwquality.conf                    >> ./$FILENAME.log 2>&1       
echo " " 												>> ./$FILENAME.log 2>&1
echo " "

if [ $OS == "AIX" ]; then
	echo "========== $PASSWD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $LOGIN_CONF "										>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $INETD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SSH_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $PROFILE "										>> ./$FILENAME.log 2>&1
		(cat $PROFILE)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SYSLOG_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SYSLOG_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SMTP_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SMTP_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== lsuser "									>> ./$FILENAME.log 2>&1
		lsuser -a account_locked time_last_login ALL | grep -v account_locked=true		>> ./$FILENAME.log 2>&1
	echo " "											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1

	echo "========== LastCmd "									>> ./$FILENAME.log 2>&1
		last											>> ./$FILENAME.log 2>&1
	echo ""												>> ./$FILENAME.log 2>&1
	echo "========== lsuser -f ALL "								>> ./$FILENAME.log 2>&1
		lsuser -f ALL
	echo " "											>> ./$FILENAME.log 2>&1
	echo " " 											>> ./$FILENAME.log 2>&1
elif [ $OS = "HP-UX" ]; then
	echo "========== $PASSWD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $LOGIN_CONF "										>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $INETD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SSH_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $PROFILE "										>> ./$FILENAME.log 2>&1
		(cat $PROFILE)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SYSLOG_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SYSLOG_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SMTP_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SMTP_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1
elif [ $OS == "Linux" ]; then
	echo "========== $PASSWD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $LOGIN_CONF "										>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $INETD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $XINETD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $XINETD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SSH_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $PROFILE "										>> ./$FILENAME.log 2>&1
		(cat $PROFILE)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SYSLOG_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SYSLOG_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SMTP_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SMTP_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== /etc/rsyslog.conf "									>> ./$FILENAME.log 2>&1
		cat /etc/rsyslog.conf										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== chkconfig "									>> ./$FILENAME.log 2>&1
		chkconfig										>> ./$FILENAME.log 2>&1
elif [ $OS == "SunOS" ]; then
	echo "========== $PASSWD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $PASSWD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $LOGIN_CONF "										>> ./$FILENAME.log 2>&1
		(cat $LOGIN_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $INETD_CONF "										>> ./$FILENAME.log 2>&1
		(cat $INETD_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SSH_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SSH_CONF)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $PROFILE "										>> ./$FILENAME.log 2>&1
		(cat $PROFILE)											>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SYSLOG_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SYSLOG_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

	echo "========== $SMTP_CONF "										>> ./$FILENAME.log 2>&1
		(cat $SMTP_CONF)										>> ./$FILENAME.log 2>&1
	echo " "												>> ./$FILENAME.log 2>&1
	echo " " 												>> ./$FILENAME.log 2>&1

										>> ./$FILENAME.log 2>&1
fi

echo "================== finish of Script ========================"					>> ./$FILENAME.log 2>&1
echo " "
echo "================== finish of Script ========================"
date
date													>> ./$FILENAME.log 2>&1

echo "완료파일은 정보보안 담당자에게 전달 부탁 드립니다."

exit 0