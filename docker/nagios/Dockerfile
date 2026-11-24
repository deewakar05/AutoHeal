FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    APACHE_RUN_USER=nagios \
    APACHE_RUN_GROUP=nagios \
    APACHE_RUN_DIR=/tmp/apache2 \
    APACHE_PID_FILE=/tmp/apache2/apache2.pid \
    APACHE_LOCK_DIR=/tmp/apache2 \
    APACHE_LOG_DIR=/tmp/apache2/logs \
    NAGIOS_CGI_CONFIG=/tmp/nagios-cfg/cgi.cfg

RUN apt-get update && apt-get install -y --no-install-recommends \
        nagios4 \
        nagios4-cgi \
        monitoring-plugins-basic \
        nagios-nrpe-plugin \
        apache2 \
        apache2-utils \
        libapache2-mod-php \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod cgi rewrite auth_basic authn_file authz_user env \
    && a2dissite 000-default \
    && a2disconf nagios4-cgi 2>/dev/null || true

RUN printf 'Listen 8081\n' > /etc/apache2/ports.conf \
    && sed -i 's/^Mutex .*/Mutex pthread/' /etc/apache2/apache2.conf \
    && mkdir -p /opt/nagios/etc/objects /opt/nagios/scripts /var/lib/nagios4/rw /var/lib/nagios4/spool/checkresults \
    && chown -R nagios:nagios /var/lib/nagios4 /opt/nagios

COPY --chmod=0644 nagios/etc/nagios.cfg /opt/nagios/etc/nagios.cfg
COPY --chmod=0644 nagios/etc/resource.cfg /opt/nagios/etc/resource.cfg
COPY --chmod=0644 nagios/etc/cgi.cfg.template /opt/nagios/etc/cgi.cfg.template
COPY --chmod=0644 nagios/etc/apache2-nagios.conf /etc/apache2/sites-available/nagios-autoheal.conf
COPY --chmod=0644 nagios/etc/objects/*.cfg /opt/nagios/etc/objects/
COPY --chmod=0755 nagios/scripts/nagios_notify.py /opt/nagios/scripts/nagios_notify.py
COPY --chmod=0755 docker/nagios/entrypoint.sh /usr/local/bin/nagios-entrypoint.sh

RUN a2ensite nagios-autoheal \
    && mkdir -p /tmp/apache2/logs /tmp/nagios4/archives /tmp/nagios4/tmp /tmp/nagios4/spool/checkresults \
    && chown -R nagios:nagios /tmp/apache2 /tmp/nagios4 \
    && ln -sf /opt/nagios/etc/nagios.cfg /etc/nagios4/nagios.cfg \
    && ln -sf /tmp/nagios-cfg/cgi.cfg /etc/nagios4/cgi.cfg \
    && /usr/sbin/nagios4 -v /opt/nagios/etc/nagios.cfg \
    && apache2 -t

USER nagios

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD ["sh", "-c", "test -s /tmp/nagios4/nagios4.pid && kill -0 \"$(cat /tmp/nagios4/nagios4.pid)\" && /usr/lib/nagios/plugins/check_http -H 127.0.0.1 -p 8081 -u /nagios4/ -e 401 -t 3 >/dev/null"]

ENTRYPOINT ["/usr/local/bin/nagios-entrypoint.sh"]
