# https://hub.docker.com/_/centos/
# https://hub.docker.com/_/fedora/
ARG IMAGE
ARG IMAGE_VER
FROM $IMAGE:$IMAGE_VER
MAINTAINER Adel "0x4D31" Karimi

ARG SSHCLIENT
ARG SSHCLIENT_VER
# Install the SSH client
RUN yum -y install $SSHCLIENT-$SSHCLIENT_VER && yum clean all
