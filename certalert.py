#!/usr/bin/env python3

import argparse
import sys
import ipaddress as ipa
import threading
import queue
import time
import socket
import ssl
from OpenSSL import crypto
from datetime import datetime


def parse_args():
    parser = argparse.ArgumentParser(description='Retrieve hostnames from TLS certificates',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     argument_default=argparse.SUPPRESS)

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-i', '--ip', dest='ipaddresses',
                       help='comma-separated list of IP addresses or CIDR networks (e.g. 127.0.0.1,fe80::,1.2.3.0/24)')
    group.add_argument('-f', '--file', dest='file',
                       help='file containing host port1,port2,... lines, one line per host (see README)')
    parser.add_argument('-p', '--ports', dest='ports', help='comma-separated list of ports',
                        default='443,636,993,995,8443')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=5,
                        help='set number of threads')
    parser.add_argument('-to', '--timeout', dest='timeout', type=float, default=1.0,
                        help='socket timeout')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true',
                        help='Print empty results')

    return parser.parse_args()


def scan_host(q, args):
    while not q.empty():
        try:
            ip, ports = q.get_nowait()
        except queue.Empty:
            break

        sslcontext = ssl.create_default_context()
        sslcontext.check_hostname = False
        sslcontext.verify_mode = ssl.CERT_NONE

        for port in ports:
            try:
                if type(ip) is ipa.IPv6Address:
                    s = sslcontext.wrap_socket(socket.socket(socket.AF_INET6))
                    # I had mixed success with IPv6, but on a my dual-stack system it seemed to work fine
                    s.settimeout(args.timeout)
                    s.connect((str(ip), port, 0, 0))
                else:
                    s = sslcontext.wrap_socket(socket.socket())
                    s.settimeout(args.timeout)
                    s.connect((str(ip), port))

                # I needed to use OpenSSL instead of the dict returned by getpeercert
                # It turned out that I have to set verify_mode to ssl.CERT_NONE (see above),
                # but with this set, s.getpeercert() returns an empty dict. So I fetch the binary cert
                # and parse it using OpenSSL
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, s.getpeercert(True))
                asn1_time = cert.get_notAfter().decode()
                if not asn1_time.lower().endswith('z'):
                    print('Timestamp not UTC!')
                now = datetime.utcnow()
                cert_expiry = None
                try:
                    cert_expiry = datetime.strptime(asn1_time, '%Y%m%d%H%M%SZ')
                except ValueError:
                    pass

                if cert_expiry is not None:
                    if now >= cert_expiry:
                        print(f'Certificate at {ip}:{port} has expired!')
                    elif (cert_expiry - now).days <= 7:
                        print(f'Certificate at {ip}:{port} will expire in {(cert_expiry - now).days} days!')
                
                # parse the subject out of the
            except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
                # something broke, or the port does not do TLS, we just skip it
                pass


def main():
    # main() just creates -t threads, puts the targets in a queue and runs the threads.
    # then it just periodically checks if the queue is empty and if all threads are finished
    # if this happens, the program exits
    args = parse_args()

    # all targets are written to a queue. Each thread will pick the next available target from the queue.
    target_queue = queue.Queue()

    try:
        if 'ipaddresses' in args:
            items = [i for i in args.ipaddresses.split(',')]
            ports = set([int(p) for p in args.ports.split(',')])  # convert list comprehension to set for unique values
            for item in items:
                if '/' in item:
                    network = ipa.ip_network(item, strict=False)
                    for host in network.hosts():
                        target_queue.put((host, ports))
                else:
                    target_queue.put((ipa.ip_address(item), ports))
        else:
            lines = [l.strip() for l in open(args.file, 'r').readlines()]
            for line in lines:
                if ' ' in line:
                    ip, ports = line.split(' ', 1)
                    if len(ports.strip()) == 0:
                        # the line contained spaces but nothing after, so use default ports instead
                        ports = args.ports
                else:
                    ip = line
                    ports = args.ports
                ports = set([int(p) for p in ports.split(',')])  # convert list comprehension to set for unique values
                if '/' in ip:
                    print(ip)
                    network = ipa.ip_network(ip, strict=False)
                    for host in network.hosts():
                        target_queue.put((host, ports))
                else:
                    ip = ipa.ip_address(ip)
                    target_queue.put((ip, ports))
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
        sys.exit(1)

    # create args.threads threads, start them and add them to the list
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=scan_host, args=(target_queue, args))
        t.start()
        threads.append(t)

    while True:
        try:
            # periodically check if the queue still contains targets and if the threads are still running
            time.sleep(0.5)
            if target_queue.empty() and True not in [t.is_alive() for t in threads]:
                # queue is empty and all threads are done, we can safely exit
                sys.exit(0)

        except KeyboardInterrupt:
            # Ctrl+C was pressed: empty the queue and wait for the threads to finish
            # each thread will return once the queue is empty
            while not target_queue.empty():
                try:
                    target_queue.get(block=False)
                except queue.Empty:
                    pass
            sys.exit(0)


if __name__ == '__main__':
    main()
