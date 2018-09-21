# https://hub.docker.com/_/alpine/
ARG IMAGE
ARG IMAGE_VER
FROM $IMAGE:$IMAGE_VER
MAINTAINER Adel "0x4D31" Karimi

ARG SSHCLIENT
ARG SSHCLIENT_VER
# Install the SSH client
RUN apk --no-cache add $SSHCLIENT=$SSHCLIENT_VER
