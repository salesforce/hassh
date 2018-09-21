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
