FROM nginx:alpine

COPY docker/socket-proxy/nginx.conf /etc/nginx/nginx.conf

EXPOSE 2375

HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=5s \
    CMD wget -q -O /dev/null http://127.0.0.1:2375/_ping

CMD ["nginx", "-g", "daemon off;"]
