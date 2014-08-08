#!/bin/sh
####
#
# SuSE master control security mechanism for the daily/weekly/monthly
# security checks, by Marc Heuse <marc@suse.de>, version 2.0
#
####
VERSION="v2.0"

test -e /etc/rc.config || touch /etc/rc.config	# prevent errors on non-SuSE
. /etc/rc.config
test -z "$SECCHK_USER" && SECCHK_USER="root"

function syntax () {
    /bin/echo "Syntax: $0 "'daily|weekly|monthly'
    exit 1
}
function disclaimer () {
    /bin/echo
    /bin/echo "DISCLAIMER"
    /bin/echo
    /bin/echo "Please note that these security checks are neither complete nor reliable."
    /bin/echo "Any attacker with proper experience and root access to your system can"
    /bin/echo "deceive *any* security check!"
    /bin/echo
}

test -z "$1" && syntax
. /etc/rc.config

export PATH="/sbin:/usr/sbin:/bin:/usr/bin"
umask 077
test -x "/usr/sbin/sendmail" && MAILER="/usr/sbin/sendmail"
test -z "$MAILER" && test -x "/usr/bin/mailx" && MAILER="/usr/bin/mailx"
test -z "$MAILER" && test -x "/usr/lib/sendmail" && MAILER="/usr/lib/sendmail"
test -z "$MAILER" && echo "Can not find a suitable mailer!"
test -z "$MAILER" && exit 1
test -z "$SEC_BIN" && SEC_BIN="/usr/lib/secchk"
test -z "$SEC_DATA" && SEC_VAR="/var/lib/secchk"
export MAILER
SEC_DATA="$SEC_VAR/data"
OUT1="$SEC_VAR/security-report-daily.new"
OLD1="$SEC_VAR/security-report-daily"
OUT2="$SEC_VAR/security-report-weekly.new"
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

test "$1" = "daily" && (
 /bin/sh "$SEC_BIN/security-daily.sh" 1> "$OUT1"
 /usr/bin/diff -q -w "$OLD1" "$OUT1" 1> /dev/null || (
    {
      echo "To: $SECCHK_USER"
      echo -e "Subject: Local Daily Security for `hostname`: Changes\n"
      echo "SuSE daily security check $VERSION by Marc Heuse <marc@suse.de>"
      echo "This is an automated mail by the seccheck tool. If you want to disable this"
      echo "service, just type \"mv /etc/cron.d/seccheck /etc/cron.d_seccheck.save\"."
      disclaimer
      echo -e "Changes in your daily security configuration of `hostname`:\n"
      /usr/bin/diff -u -w "$OLD1" "$OUT1" | sed 's/^@@.*/\
* Changes (+: new entries, -: removed entries):\
	/' | egrep '^[+*-]|^$' |sed 's/^+++/NEW:/' | sed 's/^---/OLD:/' | sed 's/^[+-]/& /'
    } | $MAILER "$SECCHK_USER"
    /bin/mv "$OUT1" "$OLD1"
 )
 rm -f "$OUT1"
)

test "$1" = "weekly" && (
 /bin/sh "$SEC_BIN/security-weekly.sh" 1> "$OUT2"
 if [ -s "$OUT2" ]; then
    {
      echo "To: $SECCHK_USER"
      echo -e "Subject: Local Weekly Security for `hostname`: Changes\n"
      echo "SuSE weekly security check $VERSION by Marc Heuse <marc@suse.de>"
      echo "This is an automated mail by the seccheck tool. If you want to disable this"
      echo "service, just type \"mv /etc/cron.d/seccheck /etc/cron.d_seccheck.save\"."
      disclaimer
      echo -e "Changes in your weekly security configuration of `hostname`:\n"
      cat "$OUT2"
    } | $MAILER "$SECCHK_USER"
    mv "$OUT2" "$OLD2"
 fi
 rm -f "$OUT2"
)

test "$1" = "monthly" && (
 test -s "$OLD1" || /bin/sh "$SEC_BIN/security-daily.sh" 1> "$OLD1"
 test -e "$SEC_DATA/devices" || /bin/sh "$SEC_BIN/security-weekly.sh" 1> "$OLD2"
 {
      echo "To: $SECCHK_USER"
      echo -e "Subject: Local Monthly Security for `hostname`: Complete\n"
      echo "SuSE monthly security check $VERSION by Marc Heuse <marc@suse.de>"
      echo "This is an automated mail by the seccheck tool. If you want to disable this"
      echo "service, just type \"mv /etc/cron.d/seccheck /etc/cron.d_seccheck.save\"."
      disclaimer
      echo -e "Complete monthly listing of `hostname`:\n"
      /bin/sh "$SEC_BIN/security-monthly.sh"
 } | tee "$OLD3" | $MAILER "$SECCHK_USER"
)

exit 0
