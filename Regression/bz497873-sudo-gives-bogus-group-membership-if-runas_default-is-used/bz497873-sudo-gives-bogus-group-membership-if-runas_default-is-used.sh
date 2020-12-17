#!/bin/bash

SCRIPT_NAME="`echo ${0} | sed 's/\.\///'`";
SCRIPT_INFO="RHTS script \"${SCRIPT_NAME}\" by amarecek@redhat.com";
SCRIPT_DESC="It tests sudo correctness of users' groups.";
BUG_NUMBER="`echo ${SCRIPT_NAME} | sed 's/^.*bz\([0-9]\+\).*$/\1/'`"
PASSED=0;
FAILED=0;
TESTS=0;
RETVAL=0;
CHCONFIG=0;

_CONFIG="/etc/sudoers";
_PROG="/usr/bin/sudo";
_INIT_SCRIPT="";

ITRTR=-1;
SCRIPT_DEPENDENCIES[ITRTR=`expr ${ITRTR} + 1`]="sudo";

LOG_FILE="/tmp/bz${BUG_NUMBER}.log"
USER_1="sudoswitcher"
USER_2="sudorunas"
SUDO_USER_PASSWD="redhat"
GROUP_1="sudogroup"

function dot_print() {
	# 80 chars per line
	# 76 means 80 - 4 ("PASS" or "FAIL")
	DOTLEN=76;
	MAXLEN=73;
	if [ ! -z "${1}" ]; then
		STRLEN=${#1};
		if [ ${STRLEN} -le ${MAXLEN} ]; then
			DOTS=`expr ${DOTLEN} - ${STRLEN}`;
			DOTSTR="";			
			for ((i = 0; i < ${DOTS}; i++)) do
				DOTSTR="${DOTSTR}.";
			done
			echo -n "${1}${DOTSTR}";
		else
			echo "${1}";
		fi
	fi
}

function report_print() {
	_THIS_MSG="No message was given!"
	if [ ! -z "${2}" ]; then
		_THIS_MSG="${2}"
	fi
	case "${1}" in
		"E" | "e" | "-e")
			echo "ERROR: ${_THIS_MSG}"
			;;
		"W" | "w" | "-w")
			echo "WARNING: ${_THIS_MSG}"
			;;
		"I" | "i" | "-i")
			echo "INFO: ${_THIS_MSG}"
			;;
		*)
			echo "No operation was given! Nothing to do."
			;;
	esac
}

function help() {
	echo "${SCRIPT_INFO}";
	echo "${SCRIPT_DESC}";
	echo "USAGE: ${0}";
	echo " * must be executed under ROOT user";
	echo "Script dependencies:";
	for ((i = 0; i < ${#SCRIPT_DEPENDENCIES[*]}; i++)) do
		if [ ! -z ${SCRIPT_DEPENDENCIES[${i}]} ]; then
			echo " - ${SCRIPT_DEPENDENCIES[${i}]}";
		fi
	done
}

function print_stats() {
	echo "*** Test statistics ***";
	echo "PASSED: ${PASSED}";
	echo "FAILED: ${FAILED}";
	echo "ALL TESTS: ${TESTS}";
	TEST_RESUL="FAIL";
	if [ ${RETVAL} == 0 ]; then
		TEST_RESUL="PASS";
	fi
	echo;
	echo ".------------------------------------------------------------------------------.";
	echo "| TEST RESULT.............................................................${TEST_RESUL} |";
	echo "'------------------------------------------------------------------------------'";
	echo;
}

function finish() {
	if [ ${CHCONFIG} -ne 0 ]; then
		restore;
	fi
	print_stats;
	echo "Exiting now with return value: ${RETVAL}";
	exit ${RETVAL};
}

function stats() {
	if [ ! -z "${1}" ]; then
		case "${1}" in
			0)
				PASSED=`expr ${PASSED} + 1`;
				TESTS=`expr ${TESTS} + 1`;
				;;
			666)
				FAILED=`expr ${FAILED} + 1`;
				TESTS=`expr ${TESTS} + 1`;
				RETVAL=1;
				finish;
				;;
			*)
				FAILED=`expr ${FAILED} + 1`;
				TESTS=`expr ${TESTS} + 1`;
				RETVAL=1;
				;;
		esac
	fi
}

function fail_reason() {
	if [ ! -z "${1}" ]; then
		echo " \`----- ${1}";
	fi
	if [ ! -z "${2}" ]; then
		echo "            \`----- Error code: ${2}";
	fi
}

function result() {
	if [ ! -z "${1}" ]; then
		if [ "${1}" == "0" ]; then
			echo "PASS";
			stats 0;
		else
			echo "FAIL";
			if [ ! -z "${2}" ]; then
				fail_reason "${2}" "${1}";
			fi
			if [ "${3}" == "1" ]; then
				stats 666;
			else
				stats ${1};
			fi
		fi
	fi
}

function prerun_check() {
	if [ ${UID} -ne 0 ]; then
		report_print "E" "You must be ROOT for running this script!";
		stats 666;
	fi
	for ((i = 0; i < ${#SCRIPT_DEPENDENCIES[*]}; i++)) do
		if [ ! -z ${SCRIPT_DEPENDENCIES[${i}]} ]; then
			if [ ! -z "`rpm -q ${SCRIPT_DEPENDENCIES[${i}]} | grep 'not installed'`" ]; then
				echo "${SCRIPT_DEPENDENCIES[${i}]} is not installed. Trying to install it...";
				yum install ${SCRIPT_DEPENDENCIES[${i}]};
				if [ $? != 0 ]; then
					report_print "E" "You have to install ${SCRIPT_DEPENDENCIES[${i}]} first!";
					stats 666;
				fi
			fi
		fi
	done
	if [ ! -z "${_CONFIG}" ]; then
		if [ ! -f ${_CONFIG} ]; then
			report_print "E" "Config file does not exist!";
			stats 666;
		fi
	fi
}

function backup() {
	if [ -f ${_CONFIG} ]; then
		cp ${_CONFIG} ${_CONFIG}.old;
		if [ $? -ne 0 ]; then
			report_print "E" "Couldn't backup config file!";
			stats 666;
		fi
	else
		report_print "E" "Couldn't backup config file! Is service not installed?";
		stats 666;
	fi
	echo "Config file has been backuped successfully.";
	return 0;
}

function restore() {
	CHCONFIG=0;
	if [ -f ${_CONFIG}.old ]; then
		mv ${_CONFIG}.old ${_CONFIG};
		if [ $? -ne 0 ]; then
			RETVAL=1;
			report_print "E" "Couldn't restore config file!";
			finish;
		fi
	else
		RETVAL=1;
		report_print "E" "Couldn't restore config file!";
		finish;
	fi
	echo "Config file has been restored successfully.";
	return 0;
}

function make_config() {
	backup;
	echo "#***** Generated by ${0} *****" > ${_CONFIG};
	cat <<EOF >> ${_CONFIG};
Cmnd_Alias NETWORKING = /sbin/route, /sbin/ifconfig, /bin/ping, /sbin/dhclient, /usr/bin/net, /sbin/iptables, /usr/bin/rfcomm, /usr/bin/wvdial, /sbin/iwconfig, /sbin/mii-tool
Cmnd_Alias SOFTWARE = /bin/rpm, /usr/bin/up2date, /usr/bin/yum
Cmnd_Alias SERVICES = /sbin/service, /sbin/chkconfig
Cmnd_Alias LOCATE = /usr/bin/updatedb
Cmnd_Alias STORAGE = /sbin/fdisk, /sbin/sfdisk, /sbin/parted, /sbin/partprobe, /bin/mount, /bin/umount
Cmnd_Alias DELEGATING = /usr/sbin/visudo, /bin/chown, /bin/chmod, /bin/chgrp 
Cmnd_Alias PROCESSES = /bin/nice, /bin/kill, /usr/bin/kill, /usr/bin/killall
Cmnd_Alias DRIVERS = /sbin/modprobe
Defaults    !requiretty
Defaults    !authenticate
Defaults    env_reset
Defaults    env_keep = "COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR \
                        LS_COLORS MAIL PS1 PS2 QTDIR USERNAME \
                        LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION \
                        LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC \
                        LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS \
                        _XKB_CHARSET XAUTHORITY"
Defaults    always_set_home, runas_default=${USER_2}
root	ALL=(ALL) 	ALL
%${GROUP_1} ALL=(${USER_2}) ALL
EOF
	CHCONFIG=1;
	return 0;
}

function user_manager {
	USER_HELP="  *For the next time choose one of followings: add / del / check"
	if [ -z "${1}" ]; then
		echo "No operation has been given! Nothing to do..."
		echo "${USER_HELP}"
		return 1
	elif [ -z "${2}" ]; then
		return `user_manager nouser`
	else
		case "${1}" in
			"add")
				user_manager del ${2} 2>> /dev/null >> /dev/null
				#useradd -s /bin/bash -d /home/${2} -m ${2} 2>> /dev/null >> /dev/null
				useradd -s /bin/bash -d /home/${2} -m ${2}
				if [ $? != 0 ]; then
					return 1
				fi
				if [ ! -z "${3}" ]; then
					#echo ${3} | passwd --stdin ${2} 2>> /dev/null >> /dev/null
					echo ${3} | passwd --stdin ${2}
					if [ $? != 0 ]; then
						return 1
					fi
				fi			
				return 0
				;;
			"del")
                sleep 1  # wait a bit before deleting a user to avoid race condition
				if [ ! -z "`grep ${2} /etc/passwd`" ]; then
					#userdel -r ${2} 2>> /dev/null >> /dev/null
					userdel -fr ${2}
					if [ $? != 0 ]; then
						return 1
					fi
				else
					return 1
				fi
				return 0
				;;
			"check")
				if [ ! -z "`grep ${2} /etc/passwd`" ]; then
					return 0
				fi
				return 1
				;;
			"nouser")
				echo "No user has been given! Nothing to do..."
				return 1
				;;
			*)
				echo "Bad operation has been given! Nothing to do..."
				echo "${USER_HELP}"
				return 1
				;;
		esac
	fi
	return 0
}

function prerun() {
	dot_print "Adding user '${USER_1}'"
	user_manager add ${USER_1} ${SUDO_USER_PASSWD}
	result $? "Can't add user '${USER_1}'" 1
	dot_print "Adding user '${USER_2}'"
	user_manager add ${USER_2} ${SUDO_USER_PASSWD}
	result $? "Can't add user '${USER_2}'"
	if [ $? != 0 ]; then
		dot_print "Deleting user '${USER_1}'"
		user_manager del ${USER_1}
		result $? "Can't delete user '${USER_1}'"
		finish
	fi
	dot_print "Adding group '${GROUP_1}'"
	ERRMSG=`groupadd ${GROUP_1} 2>&1`
	result $? ${ERRMSG}
	if [ $? != 0 ]; then
		dot_print "Deleting user '${USER_1}'"
		user_manager del ${USER_1}
		result $? "Can't delete user '${USER_1}'"
		dot_print "Deleting user '${USER_2}'"
		user_manager del ${USER_2}
		result $? "Can't delete user '${USER_2}'"
		finish
	fi
	dot_print "Adding user '${USER_1}' to group '${GROUP_1}'"
	ERRMSG=`usermod -G ${GROUP_1} ${USER_1} 2>&1`
	result $? ${ERRMSG}
}

function postrun() {
	dot_print "Deleting group '${GROUP_1}'"
	ERRMSG=`groupdel ${GROUP_1} 2>&1`
	result $? ${ERRMSG}
	dot_print "Deleting user '${USER_1}'"
	user_manager del ${USER_1}
	result $? "Can't delete user '${USER_1}'"
	dot_print "Deleting user '${USER_2}'"
	user_manager del ${USER_2}
	result $? "Can't delete user '${USER_2}'"
	if [ ! -z "${LOG_FILE}" ]; then
		echo
		echo "****** Full log ******"
		cat ${LOG_FILE}
		echo "**********************"
		echo
		rm -rf ${LOG_FILE} 2>> /dev/null >> /dev/null
	fi
}


# **************** MAIN TEST ****************
function run() {
	prerun_check
	make_config
	prerun
	dot_print "Creating log file"
	echo > ${LOG_FILE} && chown ${USER_1}:${USER_1} ${LOG_FILE} && chmod 0664 ${LOG_FILE}
	if [ $? != 0 ]; then
		echo "FAIL"
		fail_reason "Can't create log file!"
		postrun
		stats 666
	else
		echo "PASS"
		stats 0
	fi
	dot_print "Running 'id' as '${USER_1}'"
	ERRMSG=`su ${USER_1} -c 'id' 2>&1`
	RV=$?
	if [ ! -z "`echo \"${ERRMSG}\" | grep \"${GROUP_1}\"`" ]; then
		result ${RV}
	else
		result 1 "Returned value was: ${RV}"
	fi
	echo "id:" >> ${LOG_FILE}
	echo ${ERRMSG} >> ${LOG_FILE}
	echo >> ${LOG_FILE}
	dot_print "Running 'sudo id' as '${USER_1}'"
	ERRMSG=`su ${USER_1} -c 'sudo id 2>&1' 2>&1`
	RV=$?
	if [ ! -z "`echo \"${ERRMSG}\" | grep \"groups=0(root)\"`" ]; then
		result 1 "Returned value was: ${RV}"
	else
		result ${RV}
	fi
	echo "sudo id:" >> ${LOG_FILE}
	echo ${ERRMSG} >> ${LOG_FILE}
	postrun
}
# **************** /MAIN TEST ****************

# **************** MAIN PROGRAM ****************
case "${1}" in
	"help" | "--help" | "-h")
		help
		;;
	*)
		run
		;;
esac
finish;
# **************** /MAIN PROGRAM ****************
