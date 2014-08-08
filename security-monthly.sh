#!/bin/sh
####
#
# SuSE monthly security check v2.0 by Marc Heuse <marc@suse.de>
#
####

. /etc/rc.config

export PATH="/sbin:/usr/sbin:/bin:/usr/bin"
umask 077
test -z "$SEC_BIN" && SEC_BIN="/usr/lib/secchk"
test -z "$SEC_VAR" && SEC_VAR="/var/lib/secchk"
SEC_DATA="$SEC_VAR/data"
OLD1="$SEC_VAR/security-report-daily"
OLD2="$SEC_VAR/security-report-weekly"
OLD3="$SEC_VAR/security-report-monthly"
if [ ! -d "$SEC_VAR" ]; then
    rm -rf "$SEC_VAR"
    mkdir "$SEC_VAR" || exit 1
fi
if [ ! -d "$SEC_DATA" ]; then
    rm -rf "$SEC_DATA"
    mkdir "$SEC_DATA" || exit 1
fi
for i in "$OLD1" "$OLD2" "$OLD3" ; do
    if [ "$i" != "" ]; then
        if [ ! -e "$i" ]; then
    	    touch "$i"
        fi
    fi
done
for i in "$SEC_DATA/rpm-md5" "$SEC_DATA/sbit" "$SEC_DATA/write" "$SEC_DATA/devices" ; do
    if [ ! -e "$i" ] ; then
        touch "$i"
    fi
done

echo -e '\nNOTE: have you checked http://www.suse.de/security for security updates?!\n'

cat "$OLD1"

if [ -x /usr/sbin/john -a -x /usr/sbin/unshadow ]; then
    echo -e '\nComplete list of user accounts with guessable passwords:'
    unshadow /etc/passwd /etc/shadow > $SEC_VAR/passwd
    john -show "$SEC_VAR/passwd" | sed -n 's/:.*//p'
    /bin/rm -f $SEC_VAR/passwd
fi

echo -e '\nComplete list of unused user accounts which have a password assigned:'
$SEC_BIN/checkneverlogin

echo -e '\nComplete list of writeable and executeable programs:'
cat "$SEC_DATA/write-bin"

echo -e '\nComplete list of suid/sgid files:'
cat "$SEC_DATA/sbit"

echo -e '\nComplete list of world writeable files:'
cat "$SEC_DATA/write"

echo -e '\nComplete list of all changed installed packages:'
cat "$SEC_DATA/rpm-md5"

echo -e '\nComplete list of (char/block) devices:'
cat "$SEC_DATA/devices"

#echo -e '\nComplete list of x:\n'
#cat "$SEC_DATA/perms"

exit 0
