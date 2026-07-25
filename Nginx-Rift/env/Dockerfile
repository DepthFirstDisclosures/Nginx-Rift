FROM ubuntu@sha256:962f6cadeae0ea6284001009daa4cc9a8c37e75d1f5191cf0eb83fe565b63dd7
ENV DEBIAN_FRONTEND=noninteractive

ARG UBUNTU_SNAPSHOT=20260522T220000Z
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && printf '%s\n' \
        "deb [snapshot=${UBUNTU_SNAPSHOT}] http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse" \
        "deb [snapshot=${UBUNTU_SNAPSHOT}] http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse" \
        "deb [snapshot=${UBUNTU_SNAPSHOT}] http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse" \
        "deb [snapshot=${UBUNTU_SNAPSHOT}] http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse" \
        > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
        ca-certificates=20240203~22.04.1 \
        gcc=4:11.2.0-1ubuntu1 \
        make=4.3-4.1build1 \
        libpcre2-8-0=10.39-3ubuntu0.1 \
        libpcre2-dev=10.39-3ubuntu0.1 \
        libssl3=3.0.2-0ubuntu1.23 \
        libssl-dev=3.0.2-0ubuntu1.23 \
        zlib1g=1:1.2.11.dfsg-2ubuntu9.2 \
        zlib1g-dev=1:1.2.11.dfsg-2ubuntu9.2 \
        libc6=2.35-0ubuntu3.13 \
        libc6-dev=2.35-0ubuntu3.13 \
        util-linux=2.37.2-4ubuntu3.5 \
        python3=3.10.6-1~22.04.1 \
        curl=7.81.0-1ubuntu1.24 \
        libcurl4=7.81.0-1ubuntu1.24 \
        git=1:2.34.1-1ubuntu1.17 \
    && rm -rf /var/lib/apt/lists/*

ARG NGINX_REF=98fc3bb78e8daef25c3d850c9cba8c2f787fb99e
RUN git clone https://github.com/nginx/nginx.git /nginx-src \
    && cd /nginx-src && git checkout "$NGINX_REF"

RUN cd /nginx-src && ./auto/configure \
    --builddir=build \
    --with-cc-opt='-g -O2 -fno-omit-frame-pointer' \
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now' \
    --with-http_ssl_module --with-http_v2_module \
    && make -j$(nproc)

WORKDIR /app
COPY nginx.conf server.py entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p logs tmp

ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 19321
