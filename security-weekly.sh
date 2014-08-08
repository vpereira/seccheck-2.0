#!/bin/sh
####
#
# SuSE weekly security check v2.0 by Marc Heuse <marc@suse.de>
#
####
#
# TODO /etc /home /home/.* permissions
#

. /etc/rc.config

PATH=/sbin:/usr/sbin:/bin:/usr/bin
umask 077
test -z "$SEC_BIN" && SEC_BIN="/usr/lib/secchk"
test -z "$SEC_VAR" && SEC_VAR="/var/lib/secchk"
SEC_DATA="$SEC_VAR/data"
TMPDIR=`/bin/mktemp -d /tmp/.security.XXXXXX` || {
    TMPDIR="/tmp/.security-weekly.sh.redhatshouldupdatetheirmktemp.$$"
    rm -rf "$TMPDIR"
    mkdir "$TMPDIR" || exit 1
}
trap 'rm -rf $TMPDIR; exit 1' 0 1 2 3 13 15
OUT="$TMPDIR/security.out"
TMP1="$TMPDIR/security.tmp1"
TMP2="$TMPDIR/security.tmp2"

if [ ! -d "$SEC_VAR" ] ; then
    rm -rf "$SEC_VAR"
    mkdir "$SEC_VAR" || exit 1
fi
if [ ! -d "$SEC_DATA" ] ; then
    rm -rf "$SEC_DATA"
    mkdir "$SEC_DATA" || exit 1
fi

# init
for i in "$SEC_DATA/rpm-md5" "$SEC_DATA/sbit" "$SEC_DATA/write" "$SEC_DATA/devices" "$SEC_DATA/write-bin"; do
    if [ ! -e "$i" ] ; then
        touch "$i"
    fi
done

# get the ext2 and reiserfs mount points
MNT=`/bin/mount | awk '/ ext2 | reiserfs / {print$3}'| xargs -s 4000 echo`

test -z "$MAILER" && test -x "/usr/sbin/sendmail" && MAILER="/usr/sbin/sendmail"
test -z "$MAILER" && test -x "/usr/bin/mailx" && MAILER="/usr/bin/mailx"
test -z "$MAILER" && test -x "/usr/lib/sendmail" && MAILER="/usr/lib/sendmail"
test -z "$MAILER" && MAILER="mail"

# password check
if [ -x /usr/sbin/john -a -x /usr/sbin/unshadow ]; then
    echo > $SEC_VAR/dict
    cat /usr/dict/* /var/lib/john/password.lst 2> /dev/null | sort | uniq >> $SEC_VAR/dict
    unshadow /etc/passwd /etc/shadow > $SEC_VAR/passwd
    nice -n 1 john -single "$SEC_VAR/passwd" 1> /dev/null 2>&1
    nice -n 1 john -rules -w:$SEC_VAR/dict "$SEC_VAR/passwd" 1> /dev/null 2>&1
    john -show "$SEC_VAR/passwd" | sed -n 's/:.*//p' > "$OUT"
    if [ -s "$OUT" ] ; then
        for i in `cat "$OUT"`; do
             $MAILER "$i" << _EOF_
Subject: Please change your Password

Your password for account "$i" is insecure.
Please change it as soon as possible.

Yours,
        Password Checking Robot

_EOF_
        done
        printf "\nThe following user accounts have guessable passwords:\n"
	cat "$OUT"
    fi
else
    echo -e "\nPassword security checking not possible, package "john" not installed."
fi
rm -f $SEC_VAR/passwd

# neverlogin check
$SEC_BIN/checkneverlogin > "$OUT"
if [ -s "$OUT" ] ; then
	printf "\nPlease check and perhaps disable the following unused accounts:\n"
	cat "$OUT"
fi

# suid/sgid check
( nice -n 1 find $MNT \( -perm -04000 -o -perm -02000 \) -mount -type f | sort | xargs ls -cdl --full-time -- > "$SEC_DATA/sbit.new" ) 2> /dev/null
diff -uw "$SEC_DATA/sbit" "$SEC_DATA/sbit.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following files are suid/sgid:\n"
    cat "$OUT"
    mv "$SEC_DATA/sbit.new" "$SEC_DATA/sbit"
fi
rm -f "$SEC_DATA/sbit.new"

# writeable executable check
( nice -n 1 find $MNT \( -perm -30 -o -perm -3 \) -mount -type f | sort | xargs ls -cdl --full-time -- > "$SEC_DATA/write-bin.new" ) 2> /dev/null
diff -uw "$SEC_DATA/write-bin" "$SEC_DATA/write-bin.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following program executables are group/world writeable:\n"
    cat "$OUT"
    mv "$SEC_DATA/write-bin.new" "$SEC_DATA/write-bin"
fi
rm -f "$SEC_DATA/write-bin.new"

# world writable check
( nice -n 1 find $MNT -perm -2 \( -type f -o -type d \) -not -perm -01000 -mount | sort > "$SEC_DATA/write.new" ) 2> /dev/null
diff -uw "$SEC_DATA/write" "$SEC_DATA/write.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following files/directories are world writeable and not sticky:\n"
    cat "$OUT"
    mv "$SEC_DATA/write.new" "$SEC_DATA/write"
fi
rm -f "$SEC_DATA/write.new"

# md5 check
nice -n 1 rpm -Va 2> /dev/null | grep '^..5' > "$SEC_DATA/rpm-md5.new"
diff -uw "$SEC_DATA/rpm-md5" "$SEC_DATA/rpm-md5.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following programs have got a different md5 checksum since last week:\n"
    cat "$OUT"
    mv "$SEC_DATA/rpm-md5.new" "$SEC_DATA/rpm-md5"
fi
rm -f "$SEC_DATA/rpm-md5.new"

# device check
( nice -n 1 find $MNT -type c -or -type b -mount | xargs ls -cdl -- | \
	awk '{print $1 " \t" $3 " \t" $4 " \t" $5 " \t" $6 " \t" $10}' | sort +5 \
	> "$SEC_DATA/devices.new" ) 2> /dev/null
diff -uw "$SEC_DATA/devices" "$SEC_DATA/devices.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following devices were added:\n"
    cat "$OUT"
    mv "$SEC_DATA/devices.new" "$SEC_DATA/devices"
fi
rm -f "$SEC_DATA/devices.new"

####
#
# Cleaning up
#
rm -rf "$TMPDIR"
exit 0
# END OF SCRIPT
