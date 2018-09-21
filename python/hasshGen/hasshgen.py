#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause

import argparse
import json
import docker
import time
from subprocess import Popen

__author__ = "Adel '0x4D31' Karimi"
__email__ = "akarimishiraz@salesforce.com"
__version__ = "1.0"
__copyright__ = "Copyright (c) 2018, salesforce.com, inc."
__license__ = "BSD 3-Clause License"


# Default command for running hassh.py
HASSH_COMMAND = 'python3 ../hassh.py -i en1 -l json -o fingerprint.json'


def parse_cmd_args():
    """parse command line arguments"""
    desc = "A python script to automate building docker images with different\
     SSH clients/versions."
    parser = argparse.ArgumentParser(description=(desc))
    helptxt = 'Docker image name. e.g. alpine, ubuntu'
    parser.add_argument('-i', '--image', type=str, help=helptxt)
    helptxt = 'Docker image version. e.g. 18.04, latest'
    parser.add_argument('-iV', '--image_ver', type=str, help=helptxt)
    helptxt = 'SSH client name'
    parser.add_argument('-c', '--sshclient', type=str, help=helptxt)
    helptxt = 'SSH client version'
    parser.add_argument('-cV', '--sshclient_ver', type=str, help=helptxt)
    helptxt = 'Specify the Dockerfile'
    parser.add_argument('-d', '--docker_file', type=str, help=helptxt)
    helptxt = 'Server address to test the SSH connection. Default: github.com'
    parser.add_argument(
        '-s', '--server', default="github.com", type=str, help=helptxt)
    helptxt = 'Bulk mode; Specify an input file containing a list of docker\
     image, image version, sshclient and sshclient version'
    parser.add_argument('-iF', '--input_file', type=str, help=helptxt)
    helptxt = 'Set this option to automatically run hassh.py for capturing SSH\
     client fingerprints (HASSH). Specify the command for running hassh.py\
     using --cmd arg.'
    parser.add_argument(
        '-f', '--fingerprint', action="store_true", help=helptxt)
    helptxt = 'Enter the command for running hassh.py. Use with\
     -f/--fingerprint arg'
    parser.add_argument(
        '--cmd', type=str, default=HASSH_COMMAND, help=helptxt)
    return parser.parse_args()


def command_exec(container, server, ssh_client, rm):
    """Runs the container and exec SSH command"""
    client = docker.DockerClient(
                base_url='unix://var/run/docker.sock',
                version='auto')
    if 'openssh' in ssh_client:
        cmd = ('ssh -o UserKnownHostsFile=/dev/null '
               '-o StrictHostKeyChecking=no {}').format(server)
    elif 'dropbear' in ssh_client:
        cmd = 'dbclient -y {}'.format(server)
    elif 'paramiko' in ssh_client:
        cmd = 'python /tmp/paramiko_conn.py {}'.format(server)
    try:
        client.containers.run(container, command=cmd)
    except Exception as e:
        errorMsg = str(e)
        pass
    if ('Permission denied' in errorMsg or 'paramiko.ssh_exception' in errorMsg
            or 'dbclient: Connection' in errorMsg):
        out = "[+] Command successfully executed!"
    else:
        out = "[-] Error: {}".format(errorMsg)
    # Delete the image
    if rm:
        client.images.remove(image=container, force=True, noprune=True)

    return out


def main():
    """Intake arguments from the user to build docker images and initiate SSH
    connections for generating client HASSHs"""
    args = parse_cmd_args()
    tag_id = 0
    tag_name = "hasshgen:{img}{id}"
    client = docker.DockerClient(
                base_url='unix://var/run/docker.sock',
                version='auto')

    if args.input_file:
        with open(args.input_file) as file:
            input_list = json.load(file)
        # Run hassh.py
        proc = None
        if args.fingerprint and not proc:
            proc = Popen(args.cmd, shell=True)
            time.sleep(1)
        for record in input_list:
            # Find the Dockerfile
            if record['image'] in ('debian', 'ubuntu'):
                docker_file = "Dockerfile.debian"
            elif record['image'] in ('centos', 'fedora'):
                docker_file = "Dockerfile.centos"
            else:
                docker_file = "Dockerfile.{}".format(record['image'])
            # Build the docker images
            tag_id += 1
            container = tag_name.format(img=record['image'], id=tag_id)
            try:
                output = client.images.build(
                    path='.',
                    dockerfile=docker_file,
                    tag=container,
                    nocache=True,
                    rm=True,
                    forcerm=True,
                    buildargs={"IMAGE": record['image'],
                               "IMAGE_VER": record['image_ver'],
                               "SSHCLIENT": record['sshclient'],
                               "SSHCLIENT_VER": record['sshclient_ver']})
                # Docker image successfully built
                print("[+]", output[0], "successfully built")
                print("    - image: {}:{}, ssh client: {} {}".format(
                    record['image'], record['image_ver'], record['sshclient'],
                    record['sshclient_ver']))
                # Run the container and exec SSH command
                out = command_exec(
                    container, args.server, record['sshclient'], rm=False)
                if out:
                    print(out)
            except Exception as e:
                print("[-] Error:", e)
        # One more command_exec to make sure all captured (bug)
        command_exec(container, args.server, record['sshclient'], rm=True)
        # Kill hassh.py
        if proc:
            proc.kill()

    elif (args.image and args.image_ver and args.sshclient_ver
            and args.sshclient):
        container = tag_name.format(img=args.image, id=tag_id)
        try:
            output = client.images.build(
                path='.',
                dockerfile=args.docker_file,
                tag=container,
                nocache=True,
                rm=True,
                forcerm=True,
                buildargs={"IMAGE": args.image,
                           "IMAGE_VER": args.image_ver,
                           "SSHCLIENT": args.sshclient,
                           "SSHCLIENT_VER": args.sshclient_ver})
            # Docker image successfully built
            print("[+]", output[0], "successfully built")
            print("    - image: {}:{}, ssh client: {} {}".format(
                args.image, args.image_ver, args.sshclient, args.sshclient_ver))
            # Run hassh.py
            proc = None
            if args.fingerprint and not proc:
                proc = Popen(args.cmd, shell=True)
            # Run the container and exec SSH command
            time.sleep(1)
            out = command_exec(
                container, args.server, args.sshclient, rm=False)
            time.sleep(1)
            # One more command_exec to make sure all captured (bug)
            out = command_exec(
                container, args.server, args.sshclient, rm=True)
            time.sleep(1)
            if out:
                print(out)
            # Kill hassh.py
            if proc:
                proc.kill()
        except Exception as e:
            print("[-] Error:", e)


if __name__ == '__main__':
    main()
