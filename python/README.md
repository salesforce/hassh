# HASSH.py

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

HASSH is a method for creating SSH Client and Server fingerprints. This python script generates HASSH fingerprints from input PCAP files and live network traffic.

You can use [hasshGen.py](hasshGen/) to automate building docker images with different SSH clients/versions for generating HASSH fingerprints. As a demonstration we created a list ([sshClient_list](hasshGen/sshClient_list)) containing 49 different version of OpenSSH, Python’s paramiko and Dropbear SSH clients and generated a database of HASSH fingerprints in [JSON](hasshGen/hassh_fingerprints.json) and [CSV](hasshGen/hassh_fingerprints.csv) formats.

## Getting Started
1. Install tshark:
    > `apt-get install tshark`

2. Install Pipenv:
    > `pip3 install pipenv`

3. Install dependencies:
    > `pipenv install`

4. Test:
    > `$ pipenv run ./hassh.py -h`

Output:

```
usage: hassh.py [-h] [-r READ_FILE] [-d READ_DIRECTORY] [-i INTERFACE]
                [-fp {client,server}] [-da DECODE_AS]
                [-f BPF_FILTER] [-l {json,csv}] [-o OUTPUT_FILE] [-p]

A python script for extracting HASSH fingerprints

optional arguments:
  -h, --help            show this help message and exit
  -r READ_FILE, --read_file READ_FILE
                        pcap file to process
  -d READ_DIRECTORY, --read_directory READ_DIRECTORY
                        directory of pcap files to process
  -i INTERFACE, --interface INTERFACE
                        listen on interface
  -fp {client,server}, --fingerprint {client_hassh,server_hassh}
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
  -p, --print           print the output
```

## Usage
 * Live network traffic capture:
 ```
    $ ./hassh.py -i eth0 -l json -o hassh.json --print
 ```

Output:
```
[+] Server SSH_MSG_KEXINIT detected
    [ 10.10.10.10:22 -> 192.168.0.10:55106 ]
        [-] Protocol String: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
        [-] Server HASSH: d43d91bc39d5aaed819ad9f6b57b7348
        [-] Server HASSH String: curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com
[+] Client SSH_MSG_KEXINIT detected
    [ 192.168.0.10:55106 -> 10.10.10.10:22 ]
        [-] Protocol String: SSH-2.0-libssh2_1.7.0
        [-] Client HASSH: a7a87fbe86774c2e40cc4a7ea2ab1b3c
        [-] Client HASSH String: diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com;none

 ```

 JSON Output:
 ```javascript
{
  "timestamp": "2018-09-07T02:28:18.655085",
  "sourceIp": "192.168.0.10",
  "destinationIp": "10.10.10.10",
  "sourcePort": "45918",
  "destinationPort": "22",
  "client": "SSH-2.0-libssh2_1.7.0",
  "hassh": "a7a87fbe86774c2e40cc4a7ea2ab1b3c",
  "hasshAlgorithms": "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com;none",
  "hasshVersion": "0.2",
  "ckex": "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
  "ceacts": "aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc",
  "cmacts": "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com",
  "ccacts": "none"
}
{
  "timestamp": "2018-09-07T02:28:19.242684",
  "eventType": "retransmission",
  "eventMessage": "This packet is a (suspected) retransmission",
  "sourceIp": "192.168.0.10",
  "destinationIp": "10.10.10.10",
  "sourcePort": "45918",
  "destinationPort": "22"
}
```

  * Read from an input PCAP file (```-r pcapfile.pcap```) or a directory of PCAP files (```-d pcap_dir/```):

 ```
    $ ./hassh.py -r traffic.pcap -l csv -o hassh.csv --print
 ```

 CSV Output:

```
timestamp,sourceIp,destinationIp,sourcePort,destinationPort,hasshType,protocolString,hassh,hasshAlgorithms,kexAlgs,encAlgs,macAlgs,cmpAlgs
2018-09-07T02:34:50.854854,192.168.0.10,10.10.10.10,22,45918,server,"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4",d43d91bc39d5aaed819ad9f6b57b7348,"curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com","curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1","chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com","umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1","none,zlib@openssh.com"
2018-09-07T02:34:50.855180,10.10.10.10,192.168.0.10,45918,22,client,"SSH-2.0-libssh2_1.7.0",a7a87fbe86774c2e40cc4a7ea2ab1b3c,"diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com;none","diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1","aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc","hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-ripemd160@openssh.com","none"
```
