# https://hub.docker.com/_/python/
ARG IMAGE
ARG IMAGE_VER
FROM $IMAGE:$IMAGE_VER
MAINTAINER Adel "0x4D31" Karimi

# ARG SSHCLIENT
ARG SSHCLIENT_VER
# Install paramiko (ref: eduardoshanahan/paramiko)
RUN apk add --virtual .install_dependencies_paramiko \
    gcc \
    musl-dev \
    python-dev \
    libffi-dev \
    openssl-dev \
    build-base \
    py-pip \
&&  apk add zlib \
    zlib-dev \
    libssl1.0 \
    openssl-dev \
&&  pip install cffi \
&&  pip install paramiko==$SSHCLIENT_VER \
&&  apk del .install_dependencies_paramiko

# Copy the python script
COPY paramiko_conn.py /tmp/
