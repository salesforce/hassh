# https://hub.docker.com/_/debian/
# https://hub.docker.com/_/ubuntu/
ARG IMAGE
ARG IMAGE_VER
FROM $IMAGE:$IMAGE_VER
MAINTAINER Adel "0x4D31" Karimi

ENV DEBIAN_FRONTEND noninteractive
ARG SSHCLIENT
ARG SSHCLIENT_VER
# Install the SSH client
RUN apt-get update && apt-get install -y \
    $SSHCLIENT=$SSHCLIENT_VER \
 && rm -rf /var/lib/apt/lists/*
