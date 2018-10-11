#!/usr/bin/env python3
# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause

import argparse
import pyshark
import os
import json
import logging
import textwrap
from hashlib import md5

__author__ = "Adel '0x4D31' Karimi"
__email__ = "akarimishiraz@salesforce.com"
__version__ = "1.1"
__copyright__ = "Copyright (c) 2018, salesforce.com, inc."
__license__ = "BSD 3-Clause License"
__credits__ = ["Ben Reardon", "Adel Karimi", "John B. Althouse",
               "Jeff Atkinson", "Josh Atkins"]

HASSH_VERSION = '1.0'
CAP_BPF_FILTER = 'tcp port 22 or tcp port 2222'
DECODE_AS = {'tcp.port==2222': 'ssh'}

protocol_dict = {}


class color:
    CL1 = '\u001b[38;5;81m'
    CL2 = '\u001b[38;5;220m'
    CL3 = '\u001b[38;5;181m'
    CL4 = '\u001b[38;5;208m'
    END = '\033[0m'


def process_packet(packet, logf, fingerprint, pout):
    logger = logging.getLogger()
    global protocol_dict

    if not packet.highest_layer == 'SSH':
        return
    # Extract SSH identification string and correlate with KEXINIT msg
    if 'protocol' in packet.ssh.field_names:
        protocol = packet.ssh.protocol
        srcip = packet.ip.src
        dstip = packet.ip.dst
        sport = packet.tcp.srcport
        dport = packet.tcp.srcport
        key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
        protocol_dict[key] = protocol
    if 'message_code' not in packet.ssh.field_names:
        return
    if packet.ssh.message_code != '20':
        return
    if ("analysis_retransmission" in packet.tcp.field_names or
       "analysis_spurious_retransmission" in packet.tcp.field_names):
        event = event_log(packet, event="retransmission")
        if logf == 'json':
            logger.info(json.dumps(event))
        return
    # Client HASSH
    if ((fingerprint == 'client' or fingerprint == 'all')
            and int(packet.tcp.srcport) > int(packet.tcp.dstport)):
        record = client_hassh(packet)
        if logf == 'json':
            logger.info(json.dumps(record))
        elif logf == 'csv':
            csv_record = csv_logging(record)
            logger.info(csv_record)
        # Print the result
        if not pout:
            return
        tmp = textwrap.dedent("""\
            [+] Client SSH_MSG_KEXINIT detected
                {cl1}[ {sip}:{sport} -> {dip}:{dport} ]{cl1e}
                    [-] Identification String: {cl2}{proto}{cl2e}
                    [-] hassh: {cl2}{hassh}{cl2e}
                    [-] hassh Algorithms: {cl3}{hasshv}{cl3e}""")
        tmp = tmp.format(
            cl1=color.CL1,
            sip=record['sourceIp'],
            sport=record['sourcePort'],
            dip=record['destinationIp'],
            dport=record['destinationPort'],
            cl1e=color.END,
            cl2=color.CL2,
            hassh=record['hassh'],
            cl2e=color.END,
            cl3=color.CL3,
            hasshv=record['hasshAlgorithms'],
            cl3e=color.END,
            proto=record['client'])
        print(tmp)
    # Server HASSH
    elif ((fingerprint == 'server' or fingerprint == 'all')
            and int(packet.tcp.srcport) < int(packet.tcp.dstport)):
        record = server_hassh(packet)
        if logf == 'json':
            logger.info(json.dumps(record))
        elif logf == 'csv':
            csv_record = csv_logging(record)
            logger.info(csv_record)
        # Print the result
        if not pout:
            return
        tmp = textwrap.dedent("""\
            [+] Server SSH_MSG_KEXINIT detected
                {cl1}[ {sip}:{sport} -> {dip}:{dport} ]{cl1e}
                    [-] Identification String: {cl4}{proto}{cl4e}
                    [-] hasshServer: {cl4}{hasshs}{cl4e}
                    [-] hasshServer Algorithms: {cl3}{hasshsv}{cl3e}""")
        tmp = tmp.format(
            cl1=color.CL1,
            sip=record['sourceIp'],
            sport=record['sourcePort'],
            dip=record['destinationIp'],
            dport=record['destinationPort'],
            cl1e=color.END,
            cl4=color.CL4,
            hasshs=record['hasshServer'],
            cl4e=color.END,
            cl3=color.CL3,
            hasshsv=record['hasshServerAlgorithms'],
            cl3e=color.END,
            proto=record['server'])
        print(tmp)


def event_log(packet, event):
    """log the anomalous packets"""
    if event == "retransmission":
        event_message = "This packet is a (suspected) retransmission"
    # Report the event (only for JSON output)
    msg = {"timestamp": packet.sniff_time.isoformat(),
           "eventType": event,
           "eventMessage": event_message,
           "sourceIp": packet.ip.src,
           "destinationIp": packet.ip.dst,
           "sourcePort": packet.tcp.srcport,
           "destinationPort": packet.tcp.dstport}
    return msg


def client_hassh(packet):
    """returns HASSH (i.e. SSH Client Fingerprint)
    HASSH = md5(KEX;EACTS;MACTS;CACTS)
    """
    srcip = packet.ip.src
    dstip = packet.ip.dst
    sport = packet.tcp.srcport
    dport = packet.tcp.srcport
    protocol = None
    key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
    if key in protocol_dict:
        protocol = protocol_dict[key]
    # hassh fields
    ckex = ceacts = cmacts = ccacts = ""
    if 'kex_algorithms' in packet.ssh.field_names:
        ckex = packet.ssh.kex_algorithms
    if 'encryption_algorithms_client_to_server' in packet.ssh.field_names:
        ceacts = packet.ssh.encryption_algorithms_client_to_server
    if 'mac_algorithms_client_to_server' in packet.ssh.field_names:
        cmacts = packet.ssh.mac_algorithms_client_to_server
    if 'compression_algorithms_client_to_server' in packet.ssh.field_names:
        ccacts = packet.ssh.compression_algorithms_client_to_server
    # Log other kexinit fields (only in JSON)
    clcts = clstc = ceastc = cmastc = ccastc = ""
    if 'languages_client_to_server' in packet.ssh.field_names:
        clcts = packet.ssh.languages_client_to_server
    if 'languages_server_to_client' in packet.ssh.field_names:
        clstc = packet.ssh.languages_server_to_client
    if 'encryption_algorithms_server_to_client' in packet.ssh.field_names:
        ceastc = packet.ssh.encryption_algorithms_server_to_client
    if 'mac_algorithms_server_to_client' in packet.ssh.field_names:
        cmastc = packet.ssh.mac_algorithms_server_to_client
    if 'compression_algorithms_server_to_client' in packet.ssh.field_names:
        ccastc = packet.ssh.compression_algorithms_server_to_client
    if 'server_host_key_algorithms' in packet.ssh.field_names:
        cshka = packet.ssh.server_host_key_algorithms
    # Create hassh
    hassh_str = ';'.join([ckex, ceacts, cmacts, ccacts])
    hassh = md5(hassh_str.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "client": protocol,
              "hassh": hassh,
              "hasshAlgorithms": hassh_str,
              "hasshVersion": HASSH_VERSION,
              "ckex": ckex,
              "ceacts": ceacts,
              "cmacts": cmacts,
              "ccacts": ccacts,
              "clcts": clcts,
              "clstc": clstc,
              "ceastc": ceastc,
              "cmastc": cmastc,
              "ccastc": ccastc,
              "cshka": cshka}
    return record


def server_hassh(packet):
    """returns HASSHServer (i.e. SSH Server Fingerprint)
    HASSHServer = md5(KEX;EASTC;MASTC;CASTC)
    """
    srcip = packet.ip.src
    dstip = packet.ip.dst
    sport = packet.tcp.srcport
    dport = packet.tcp.srcport
    protocol = None
    key = '{}:{}_{}:{}'.format(srcip, sport, dstip, dport)
    if key in protocol_dict:
        protocol = protocol_dict[key]
    # hasshServer fields
    skex = seastc = smastc = scastc = ""
    if 'kex_algorithms' in packet.ssh.field_names:
        skex = packet.ssh.kex_algorithms
    if 'encryption_algorithms_server_to_client' in packet.ssh.field_names:
        seastc = packet.ssh.encryption_algorithms_server_to_client
    if 'mac_algorithms_server_to_client' in packet.ssh.field_names:
        smastc = packet.ssh.mac_algorithms_server_to_client
    if 'compression_algorithms_server_to_client' in packet.ssh.field_names:
        scastc = packet.ssh.compression_algorithms_server_to_client
    # Log other kexinit fields (only in JSON)
    slcts = slstc = seacts = smacts = scacts = ""
    if 'languages_client_to_server' in packet.ssh.field_names:
        slcts = packet.ssh.languages_client_to_server
    if 'languages_server_to_client' in packet.ssh.field_names:
        slstc = packet.ssh.languages_server_to_client
    if 'encryption_algorithms_client_to_server' in packet.ssh.field_names:
        seacts = packet.ssh.encryption_algorithms_client_to_server
    if 'mac_algorithms_client_to_server' in packet.ssh.field_names:
        smacts = packet.ssh.mac_algorithms_client_to_server
    if 'compression_algorithms_client_to_server' in packet.ssh.field_names:
        scacts = packet.ssh.compression_algorithms_client_to_server
    if 'server_host_key_algorithms' in packet.ssh.field_names:
        sshka = packet.ssh.server_host_key_algorithms
    # Create hasshServer
    hasshs_str = ';'.join([skex, seastc, smastc, scastc])
    hasshs = md5(hasshs_str.encode()).hexdigest()
    record = {"timestamp": packet.sniff_time.isoformat(),
              "sourceIp": packet.ip.src,
              "destinationIp": packet.ip.dst,
              "sourcePort": packet.tcp.srcport,
              "destinationPort": packet.tcp.dstport,
              "server": protocol,
              "hasshServer": hasshs,
              "hasshServerAlgorithms": hasshs_str,
              "hasshVersion": HASSH_VERSION,
              "skex": skex,
              "seastc": seastc,
              "smastc": smastc,
              "scastc": scastc,
              "slcts": slcts,
              "slstc": slstc,
              "seacts": seacts,
              "smacts": smacts,
              "scacts": scacts,
              "sshka": sshka}
    return record


def csv_logging(record):
    """generate output in csv format"""
    csv_record = ('{ts},{si},{di},{sp},{dp},{t},"{p}",{h},{v},"{ha}",'
                  '"{k}","{e}","{m}","{c}"')
    if 'hassh' in record:
        hasshType = 'client'
        kexAlgs = record['ckex']
        encAlgs = record['ceacts']
        macAlgs = record['cmacts']
        cmpAlgs = record['ccacts']
        hassh = record['hassh']
        hasshAlgorithms = record['hasshAlgorithms']
        identificationString = record['client']
    elif 'hasshServer' in record:
        hasshType = 'server'
        kexAlgs = record['skex']
        encAlgs = record['seastc']
        macAlgs = record['smastc']
        cmpAlgs = record['scastc']
        hassh = record['hasshServer']
        hasshAlgorithms = record['hasshServerAlgorithms']
        identificationString = record['server']
    csv_record = csv_record.format(
        ts=record['timestamp'], si=record['sourceIp'],
        di=record['destinationIp'], sp=record['sourcePort'],
        dp=record['destinationPort'], t=hasshType, p=identificationString,
        h=hassh, v=HASSH_VERSION, ha=hasshAlgorithms, k=kexAlgs, e=encAlgs,
        m=macAlgs, c=cmpAlgs)
    return csv_record


def parse_cmd_args():
    """parse command line arguments"""
    desc = """A python script for extracting HASSH fingerprints"""
    parser = argparse.ArgumentParser(description=(desc))
    helptxt = "pcap file to process"
    parser.add_argument('-r', '--read_file', type=str, help=helptxt)
    helptxt = "directory of pcap files to process"
    parser.add_argument('-d', '--read_directory', type=str, help=helptxt)
    helptxt = "listen on interface"
    parser.add_argument('-i', '--interface', type=str, help=helptxt)
    helptxt = "client or server fingerprint. Default: all"
    parser.add_argument(
        '-fp',
        '--fingerprint',
        default='all',
        choices=['client', 'server'],
        help=helptxt)
    helptxt = "a dictionary of {decode_criterion_string: decode_as_protocol} \
        that are used to tell tshark to decode protocols in situations it \
        wouldn't usually. Default: {'tcp.port==2222': 'ssh'}."
    parser.add_argument(
        '-da', '--decode_as', type=dict, default=DECODE_AS, help=helptxt)
    helptxt = "BPF capture filter to use (for live capture only).\
        Default: 'tcp port 22 or tcp port 2222'"
    parser.add_argument(
        '-f', '--bpf_filter', type=str, default=CAP_BPF_FILTER, help=helptxt)
    helptxt = "specify the output log format (json/csv)"
    parser.add_argument(
        '-l',
        '--log_format',
        choices=['json', 'csv'],
        help=helptxt)
    helptxt = "specify the output log file. Default: hassh.log"
    parser.add_argument(
        '-o', '--output_file', default='hassh.log', type=str, help=helptxt)
    helptxt = "save the live captured packets to this file"
    parser.add_argument(
        '-w', '--write_pcap', default=None, type=str, help=helptxt)
    helptxt = "print the output"
    parser.add_argument(
        '-p', '--print_output', action="store_true", help=helptxt)
    return parser.parse_args()


def setup_logging(logfile):
    """setup logging"""
    logger = logging.getLogger()
    handler = logging.FileHandler(logfile)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def main():
    """intake arguments from the user and extract HASSH fingerprints."""
    args = parse_cmd_args()
    setup_logging(args.output_file)
    logger = logging.getLogger()

    csv_header = ("timestamp,sourceIp,destinationIp,sourcePort,"
                  "destinationPort,hasshType,identificationString,"
                  "hassh,hasshVersion,hasshAlgorithms,kexAlgs,encAlgs,"
                  "macAlgs,cmpAlgs")
    if args.log_format == 'csv':
        logger.info(csv_header)

    # Process PCAP file
    if args.read_file:
        cap = pyshark.FileCapture(args.read_file, decode_as=args.decode_as)
        try:
            for packet in cap:
                process_packet(
                    packet,
                    logf=args.log_format,
                    fingerprint=args.fingerprint,
                    pout=args.print_output)
            cap.close()
            cap.eventloop.stop()
        except Exception as e:
            print('Error: {}'.format(e))
            pass

    # Process directory of PCAP files
    elif args.read_directory:
        files = [f.path for f in os.scandir(args.read_directory)
                 if not f.name.startswith('.') and not f.is_dir()
                 and (f.name.endswith(".pcap") or f.name.endswith(".pcapng")
                 or f.name.endswith(".cap"))]
        for file in files:
            cap = pyshark.FileCapture(file, decode_as=args.decode_as)
            try:
                for packet in cap:
                    process_packet(
                        packet,
                        logf=args.log_format,
                        fingerprint=args.fingerprint,
                        pout=args.print_output)
                cap.close()
                cap.eventloop.stop()
            except Exception as e:
                print('Error: {}'.format(e))
                pass

    # Capture live network traffic
    elif args.interface:
        # TODO: Use a Ring Buffer (LiveRingCapture), when the issue is fixed:
        # https://github.com/KimiNewt/pyshark/issues/299
        cap = pyshark.LiveCapture(
            interface=args.interface,
            decode_as=args.decode_as,
            bpf_filter=args.bpf_filter,
            output_file=args.write_pcap)
        try:
            for packet in cap.sniff_continuously(packet_count=0):
                # if len(protocol_dict) > 10000:
                # protocol_dict.clear()
                process_packet(
                    packet,
                    logf=args.log_format,
                    fingerprint=args.fingerprint,
                    pout=args.print_output)
        except (KeyboardInterrupt, SystemExit):
            print("Exiting..\nBYE o/\n")


if __name__ == '__main__':
    main()
