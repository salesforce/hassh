# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
#
# A dockerized version of hassh.py can be used to extract HASSH fingerprints from input PCAP files and live network traffic.
#
# Build the docker image using Dockerfile:
#   $ docker build -t hassh:latest .
# - Reading from input PCAP files:
#    You can mount your host ~/pcap dir to copy pcap files to the container and also keep the logs on your host:
#      $ docker run -v ~/pcap:/tmp/ -it hassh:latest -d /tmp/ -l json -o /tmp/log.json
# - Live network traffic capture:
#      $ docker run --net=host -it hassh:latest -i any --print
# Note: According to Docker's docs, the host networking driver only works on Linux hosts, and is not supported on Docker for Mac, Docker for Windows, or Docker EE for Windows Server.

FROM alpine:latest
MAINTAINER Adel Karimi (@0x4d31)
ENV DEBIAN_FRONTEND noninteractive
RUN apk --no-cache add python3 gcc \
    py-lxml tshark \
    && pip3 install pyshark
WORKDIR /opt/hassh
ADD https://raw.githubusercontent.com/salesforce/hassh/master/python/hassh.py .
ENTRYPOINT ["python3","hassh.py"]
CMD ["-h"]
