FROM alpine:3.20

RUN apk add --no-cache \
        wireguard-tools \
        iproute2 \
        openresolv \
        curl \
        bind-tools \
        iputils \
        bash \
        tcpdump

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
