#!/usr/bin/env python

import paramiko
import sys

hostname = sys.argv[1]
port = 22
usr = 'user'
pwd = 'pass'

try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    client.connect(hostname, port=port, username=usr, password=pwd)
except paramiko.SSHException as e:
    raise
