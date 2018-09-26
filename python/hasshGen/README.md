# hasshGen.py

[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Sample python script and Dockerfiles to automate building docker images with different SSH clients/versions for generating HASSH fingerprints.
As a demonstration we created a list ([sshClient_list](sshClient_list)) containing 49 different version of OpenSSH, Python’s paramiko and Dropbear SSH clients and generated a database of HASSH fingerprints in [JSON](hassh_fingerprints.json) and [CSV](hassh_fingerprints.csv) formats.

## Getting Started
1. Install Docker CE:
    > [Download Docker Engine](https://store.docker.com/search?type=edition&offering=community)

2. Install the Docker's Python library:
    > `pipenv install docker`

4. Test:
    > `pipenv run python3 hasshgen.py -h`

Output:

```
usage: hasshgen.py [-h] [-i IMAGE] [-iV IMAGE_VER] [-c SSHCLIENT]
                   [-cV SSHCLIENT_VER] [-d DOCKER_FILE] -s SERVER
                   [-iF INPUT_FILE] [-f] [--cmd CMD]

A python script to automate building docker images with different SSH
clients/versions.

optional arguments:
  -h, --help            show this help message and exit
  -i IMAGE, --image IMAGE
                        Docker image name. e.g. alpine, ubuntu
  -iV IMAGE_VER, --image_ver IMAGE_VER
                        Docker image version. e.g. 18.04, latest
  -c SSHCLIENT, --sshclient SSHCLIENT
                        SSH client name
  -cV SSHCLIENT_VER, --sshclient_ver SSHCLIENT_VER
                        SSH client version
  -d DOCKER_FILE, --docker_file DOCKER_FILE
                        Specify the Dockerfile
  -s SERVER, --server SERVER
                        Specify the server address to test the SSH connection
  -iF INPUT_FILE, --input_file INPUT_FILE
                        Bulk mode; Specify an input file containing a list of
                        docker image, image version, sshclient and sshclient
                        version
  -f, --fingerprint     Set this option to automatically run hassh.py for
                        capturing SSH client fingerprints (HASSH). Specify the
                        command for running hassh.py using --cmd arg.
  --cmd CMD             Enter the command for running hassh.py. Use with
                        -f/--fingerprint arg
```

## Usage
 * Build and run a docker image with specific SSH client/version:
```
$ python3 hasshgen.py --docker_file Dockerfile.alpine --image alpine -iV 3.6 --sshclient openssh-client --sshclient_ver 7.5_p1-r2 --server <your-ssh-server>

[+] <Image: 'hasshgen:alpine0'> successfully built
    - image: alpine:3.6, ssh client: openssh-client 7.5_p1-r2
[+] Command successfully executed!
 ```

After building the docker image, the script runs a SSH command to generate SSH connections for fingerprinting. It currently supports openssh, paramiko, and dropbear SSH clients. You can easily add other SSH clients.

 * Build docker images using an input file in this format: [sshClient_list](sshClient_list)
```
$ python3 hasshgen.py --input_file sshClient_list --server <your-ssh-server>
[+] <Image: 'hasshgen:alpine1'> successfully built
    - image: alpine:3.3, ssh client: openssh-client 7.2_p2-r3
[+] Command successfully executed!
[+] <Image: 'hasshgen:alpine2'> successfully built
    - image: alpine:3.4, ssh client: openssh-client 7.2_p2-r5
[+] Command successfully executed!
[+] <Image: 'hasshgen:alpine3'> successfully built
    - image: alpine:3.5, ssh client: openssh-client 7.4_p1-r1
[+] Command successfully executed!
```

 * You can use `-f` or `--fingerprint` arg to automatically run `hassh.py` for extracting the fingerprints. Use `--cmd` to change the default HASSH_COMMAND:
 ```
$ python3 hasshgen.py --input_file sshClient_list --server <your-ssh-server> --fingerprint --cmd 'python3 ../hassh.py -i eth0 -l json -o fingerprint.json'
 ```
