#!/bin/sh
set -eu

if [ -z "${NAGIOS_ADMIN_USER:-}" ]; then
    echo "ERROR: NAGIOS_ADMIN_USER must be set (fail-closed)." >&2
    exit 1
fi

if [ -z "${NAGIOS_ADMIN_PASSWORD:-}" ]; then
    echo "ERROR: NAGIOS_ADMIN_PASSWORD must be set (fail-closed)." >&2
    exit 1
fi

if [ -z "${AUTOHEAL_NAGIOS_WEBHOOK_SECRET:-}" ]; then
    echo "ERROR: AUTOHEAL_NAGIOS_WEBHOOK_SECRET must be set (fail-closed)." >&2
    exit 1
fi

mkdir -p \
    /tmp/nagios4/archives \
    /tmp/nagios4/tmp \
    /tmp/nagios4/spool/checkresults \
    /tmp/nagios-cfg \
    /tmp/nagios-secrets \
    /tmp/apache2/logs \
    /var/lib/nagios4/rw \
    /var/lib/nagios4/spool/checkresults

chmod 0700 /tmp/nagios-secrets

# Populate CGI config and fail-closed Basic Auth htpasswd file inside /tmp tmpfs.
escaped_user=$(printf '%s' "$NAGIOS_ADMIN_USER" | sed 's/[\\&/]/\\&/g')
sed "s/__NAGIOS_ADMIN_USER__/${escaped_user}/g" /opt/nagios/etc/cgi.cfg.template > /tmp/nagios-cfg/cgi.cfg
chmod 0644 /tmp/nagios-cfg/cgi.cfg

umask 077
printf '%s' "$NAGIOS_ADMIN_PASSWORD" | htpasswd -ciB /tmp/nagios-secrets/htpasswd "$NAGIOS_ADMIN_USER"
chmod 0600 /tmp/nagios-secrets/htpasswd

printf '%s\n' "$AUTOHEAL_NAGIOS_WEBHOOK_SECRET" > /tmp/nagios-secrets/webhook.secret
chmod 0600 /tmp/nagios-secrets/webhook.secret
umask 022

# Verify Nagios Core configuration before launching services.
/usr/sbin/nagios4 -v /opt/nagios/etc/nagios.cfg

nagios_pid=""
apache_pid=""

cleanup() {
    set +e
    if [ -n "$apache_pid" ] && kill -0 "$apache_pid" 2>/dev/null; then
        kill -TERM "$apache_pid" 2>/dev/null
        wait "$apache_pid" 2>/dev/null || true
    fi
    if [ -n "$nagios_pid" ] && kill -0 "$nagios_pid" 2>/dev/null; then
        kill -TERM "$nagios_pid" 2>/dev/null
        wait "$nagios_pid" 2>/dev/null || true
    fi
    rm -f /tmp/nagios4/nagios4.pid
}
trap cleanup INT TERM

/usr/sbin/nagios4 /opt/nagios/etc/nagios.cfg &
nagios_pid=$!
printf '%s\n' "$nagios_pid" > /tmp/nagios4/nagios4.pid

apache2 -D FOREGROUND &
apache_pid=$!

# Monitor both child processes; exit non-zero if either exits unexpectedly.
while kill -0 "$nagios_pid" 2>/dev/null && kill -0 "$apache_pid" 2>/dev/null; do
    sleep 2
done

cleanup
exit 1
