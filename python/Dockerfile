# Hassh.py works in two modes:
# 1. Live network traffic capture:
# The host networking driver only works on Linux hosts, and is not supported
# on Docker for Mac, Docker for Windows, or Docker EE for Windows Server.
#  $ docker run --net=host -it hassh -i any --print
# 2. Reading from input PCAP files:
#  $ docker run -v ~/pcap:/tmp/ -it hassh -d /tmp/ -l json -o /tmp/log.json

FROM alpine:latest
MAINTAINER Adel Karimi (@0x4d31)
ENV DEBIAN_FRONTEND noninteractive
RUN apk --no-cache add python3 gcc \
    py-lxml tshark \
    && pip3 install pyshark
WORKDIR /opt/hassh
COPY hassh.py .
ENTRYPOINT ["python3","hassh.py"]
CMD ["-h"]
