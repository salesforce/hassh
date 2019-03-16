# HASSH.py

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

HASSH is a method for creating SSH Client and Server fingerprints. This python script generates HASSH fingerprints from input PCAP files and live network traffic.

You can use [hasshGen.py](hasshGen/) to automate building docker images with different SSH clients/versions for generating HASSH fingerprints. As a demonstration we created a list ([sshClient_list](hasshGen/sshClient_list)) containing 49 different version of OpenSSH, Python’s paramiko and Dropbear SSH clients and generated a database of HASSH fingerprints in [JSON](hasshGen/hassh_fingerprints.json) and [CSV](hasshGen/hassh_fingerprints.csv) formats.

## Getting Started
1. Install Tshark. 
    > `apt-get install tshark` on Debian/Ubuntu or `yum install wireshark` on Centos 7
    

2. Install Pipenv:
    > `pip3 install pipenv`

3. Install dependencies:
    > `pipenv install`

4. Test:

To activate the virtualenv, run pipenv shell:
```
$ pipenv shell
(python-ZnElGiuE) bash-3.2$ python3 hassh.py -h
```

Alternatively, run a command inside the virtualenv with pipenv run:

```
$ pipenv run python3 hassh.py -h
```

Output:

```
usage: hassh.py [-h] [-r READ_FILE] [-d READ_DIRECTORY] [-i INTERFACE]
                [-fp {client,server}] [-da DECODE_AS] [-f BPF_FILTER]
                [-l {json,csv}] [-o OUTPUT_FILE] [-w WRITE_PCAP] [-p]

A python script for extracting HASSH fingerprints

optional arguments:
  -h, --help            show this help message and exit
  -r READ_FILE, --read_file READ_FILE
                        pcap file to process
  -d READ_DIRECTORY, --read_directory READ_DIRECTORY
                        directory of pcap files to process
  -i INTERFACE, --interface INTERFACE
                        listen on interface
  -fp {client,server}, --fingerprint {client,server}
                        client or server fingerprint. Default: all
  -da DECODE_AS, --decode_as DECODE_AS
                        a dictionary of {decode_criterion_string:
                        decode_as_protocol} that are used to tell tshark to
                        decode protocols in situations it wouldn't usually.
                        Default: {'tcp.port==2222': 'ssh'}.
  -f BPF_FILTER, --bpf_filter BPF_FILTER
                        BPF capture filter to use (for live capture only).
                        Default: 'tcp port 22 or tcp port 2222'
  -l {json,csv}, --log_format {json,csv}
                        specify the output log format (json/csv)
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        specify the output log file. Default: hassh.log
  -w WRITE_PCAP, --write_pcap WRITE_PCAP
                        save the live captured packets to this file
  -p, --print_output    print the output
```

## Usage
 * Live network traffic capture:
 ```
    $ python3 hassh.py -i eth0 -l json -o hassh.json --print
 ```

Output:
```
[+] Server SSH_MSG_KEXINIT detected
    [ 192.1.2.3:22 -> 10.1.2.3:52068 ]
        [-] Identification String: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
        [-] hasshServer: d43d91bc39d5aaed819ad9f6b57b7348
        [-] hasshServer Algorithms: curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com
[+] Client SSH_MSG_KEXINIT detected
    [ 10.1.2.3:52068 -> 192.1.2.3:22 ]
        [-] Identification String: SSH-2.0-OpenSSH_7.6
        [-] hassh: 06046964c022c6407d15a27b12a6a4fb
        [-] hassh Algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib
```

JSON Output:
 ```javascript
{
  "timestamp": "2018-09-04T18:57:03.644663",
  "sourceIp": "10.1.2.3",
  "destinationIp": "192.1.2.3",
  "sourcePort": "52068",
  "destinationPort": "22",
  "client": "SSH-2.0-OpenSSH_7.6",
  "hassh": "06046964c022c6407d15a27b12a6a4fb",
  "hasshAlgorithms": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib",
  "hasshVersion": "1.0",
  "ckex": "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c",
  "ceacts": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
  "cmacts": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "ccacts": "none,zlib@openssh.com,zlib",
  "clcts": "[Empty]",
  "clstc": "[Empty]",
  "ceastc": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
  "cmastc": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "ccastc": "none,zlib@openssh.com,zlib",
  "cshka": "ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa"
}
{
  "timestamp": "2018-09-04T18:57:04.534235",
  "eventType": "retransmission",
  "eventMessage": "This packet is a (suspected) retransmission",
  "sourceIp": "10.1.2.3",
  "destinationIp": "192.1.2.3",
  "sourcePort": "52068",
  "destinationPort": "22"
}
```

  * Reading from an input PCAP file (```-r pcapfile.pcap```) or a directory of PCAP files (```-d pcap_dir/```):

 ```
    $ python3 hassh.py -r traffic.pcap -l csv -o hassh.csv --print
 ```

CSV Output:
```
timestamp,sourceIp,destinationIp,sourcePort,destinationPort,hasshType,identificationString,hassh,hasshVersion,hasshAlgorithms,kexAlgs,encAlgs,macAlgs,cmpAlgs
2018-09-04T18:57:03.642572,192.1.2.3,10.1.2.3,22,52068,server,"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4",d43d91bc39d5aaed819ad9f6b57b7348,1.0,"curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com","curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1","chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com","umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1","none,zlib@openssh.com"
2018-09-04T18:57:03.644663,10.1.2.3,192.1.2.3,52068,22,client,"SSH-2.0-OpenSSH_7.6",06046964c022c6407d15a27b12a6a4fb,1.0,"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib","curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c","chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com","umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1","none,zlib@openssh.com,zlib"
```

## Docker

A dockerized version of hassh.py can be used to extract HASSH fingerprints from input PCAP files and live network traffic.

Build the docker image using Dockerfile:
 ```
    $ docker build -t hassh:latest .
 ```

 * Reading from input PCAP files:

You can mount your host ~/pcap dir to copy pcap files to the container and also keep the logs on your host:
 ```
    $ docker run -v ~/pcap:/tmp/ -it hassh:latest -d /tmp/ -l json -o /tmp/log.json
 ```

 * Live network traffic capture:
 ```
    $ docker run --net=host -it hassh:latest -i any --print
 ```

Note: According to Docker's [docs](https://docs.docker.com/network/host/), the host networking driver only works on Linux hosts, and is not supported on Docker for Mac, Docker for Windows, or Docker EE for Windows Server.
