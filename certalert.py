#!/usr/bin/env python3

import argparse
import ipaddress as ipa
import queue
import socket
import sqlite3
import ssl
import sys
import threading
import time
from OpenSSL import crypto
from datetime import datetime


killcmd = "PLSRETURNKTHXBYE"  # used to signal the dbthread to return
printlock = threading.Lock()


def parse_args():
    parser = argparse.ArgumentParser(description='Check sites and servers for expiring/expired TLS certificates',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     argument_default=argparse.SUPPRESS)

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-i', '--ip', dest='hosts',
                       help='comma-separated list of hostnames, IP addresses or CIDR networks (e.g. localhost,127.0.0.1,fe80::,1.2.3.0/24)')
    group.add_argument('-f', '--file', dest='file',
                       help='file containing host port1,port2,... lines, one line per host (see README)')
    parser.add_argument('-p', '--ports', dest='ports', help='comma-separated list of ports',
                        default='443,636,993,995,8443')
    parser.add_argument('-d', '--db', dest='dbfile', default='data.sqlite')
    parser.add_argument('-y', '--days', dest='days', type=int, default=7, help='days until expiry date')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=5,
                        help='set number of threads')
    parser.add_argument('-to', '--timeout', dest='timeout', type=float, default=0.5,
                        help='socket timeout')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true',
                        help='Print empty results')

    return parser.parse_args()


def scan_host(q, result_queue, args):
    while not q.empty():
        try:
            host, ports = q.get_nowait()
        except queue.Empty:
            break

        sslcontext = ssl.create_default_context()
        sslcontext.check_hostname = False
        sslcontext.verify_mode = ssl.CERT_NONE

        for port in ports:
            try:
                if type(host) is ipa.IPv6Address:
                    s = sslcontext.wrap_socket(socket.socket(socket.AF_INET6), server_hostname=str(host))
                    # I had mixed success with IPv6, but on a my dual-stack system it seemed to work fine
                    s.settimeout(args.timeout)
                    s.connect((str(host), port, 0, 0))
                else:
                    s = sslcontext.wrap_socket(socket.socket(), server_hostname=str(host))
                    s.settimeout(args.timeout)
                    s.connect((str(host), port))

                # I needed to use OpenSSL instead of the dict returned by getpeercert
                # It turned out that I have to set verify_mode to ssl.CERT_NONE (see above),
                # but with this set, s.getpeercert() returns an empty dict. So I fetch the binary cert
                # and parse it using OpenSSL
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, s.getpeercert(True))
                asn1_time = cert.get_notAfter().decode()
                if not asn1_time.lower().endswith('z'):
                    printlock.acquire()
                    print(f'Timestamp at {host}:{port} not UTC!')  # tbh, I'm not sure if this is even possible
                    printlock.release()
                now = datetime.utcnow()
                cert_expiry = None
                try:
                    cert_expiry = datetime.strptime(asn1_time, '%Y%m%d%H%M%SZ')
                except ValueError:
                    printlock.acquire()
                    print(f'[!] Can\'t parse expiry date for {host}:{port}', file=sys.stderr)
                    printlock.release()

                if cert_expiry is not None:
                    if cert.has_expired():
                        printlock.acquire()
                        print(f'[-] Certificate at {host}:{port} expired on {cert_expiry.strftime("%Y-%m-%d %H:%M:%S")}!')
                        printlock.release()
                        result_queue.put((now.strftime('%Y-%m-%d %H:%M:%SZ'), str(host), port, crypto.dump_certificate(crypto.FILETYPE_PEM, cert), cert.digest('SHA256').decode(), 1 if cert.has_expired() else 0, cert_expiry.strftime("%Y-%m-%d %H:%M:%SZ")))
                    elif (cert_expiry - now).days <= args.days:
                        printlock.acquire()
                        print(f'[!] Certificate at {host}:{port} will expire in {(cert_expiry - now).days} days, on on {cert_expiry.strftime("%Y-%m-%d %H:%M:%SZ")}!')
                        printlock.release()
                        result_queue.put((now.strftime('%Y-%m-%d %H:%M:%SZ'), str(host), port, crypto.dump_certificate(crypto.FILETYPE_PEM, cert), cert.digest('SHA256').decode(), 1 if cert.has_expired() else 0, cert_expiry.strftime("%Y-%m-%d %H:%M:%SZ")))
                    elif args.verbose:
                        printlock.acquire()
                        print(f'[+] Certificate at {host}:{port} expires on {cert_expiry.strftime("%Y-%m-%d %H:%M:%S")}')
                        printlock.release()

            except (OSError, socket.timeout):
                # something broke, or the port does not do TLS, we just skip it
                pass


def record_result(result_queue, args):
    query = 'insert into certdata values (?, ?, ?, ?, ?, ?, ?)'

    # first get a cursor to the database
    conn = sqlite3.connect(args.dbfile)
    cursor = conn.cursor()

    # check if the table we need, certdata, already exists
    cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='certdata'")
    if cursor.fetchone()[0] != 1:
        # if we are here, certdata does not exist, so we create it
        cursor.execute("""CREATE TABLE certdata (
            date TEXT,
            host TEXT,
            port INTEGER,
            certificate BLOB,
            fingerprint TEXT,
            expired INTEGER,
            expirydate TEXT)""")

    # we are done with housekeeping, let's start the main loop
    while True:
        try:
            result = result_queue.get(timeout=1)
            if result == killcmd:
                conn.close()
                return
            # the result was not our killcommand, so it's a regular result, we will write it to the DB
            # first, check if the combo host:port:fingerprint is already in the db
            # if so, update the date field and the expired field, otherwise insert the whole set
            date, host, port, _, fingerprint, expired, _ = result
            cursor.execute(f'select rowid,host,port from certdata where fingerprint="{fingerprint}"')
            dbdata = cursor.fetchall()
            record_already_present = False
            if len(dbdata) > 0:
                for r, h, p in dbdata:
                    if host == h and port == p:
                        cursor.execute(f'update certdata set date="{date}", expired={expired} where rowid={r}')
                        record_already_present = True
            if not record_already_present:
                cursor.execute(query, result)
            conn.commit()
        except queue.Empty:
            # we will keep going even if the result queue is empty
            pass


def main():
    # main() just creates -t threads, puts the targets in a queue and runs the threads.
    # then it just periodically checks if the queue is empty and if all threads are finished
    # if this happens, the program exits
    args = parse_args()

    # all targets are written to a queue. Each thread will pick the next available target from the queue.
    target_queue = queue.Queue()  # contains tuples: (ip_address, hostname, port list)
    result_queue = queue.Queue()

    try:
        # This block fills the target queue.
        if 'hosts' in args:
            # -i/--ip was used
            items = [i for i in args.hosts.split(',')]  # split the parameter into a list
            ports = set([int(p) for p in args.ports.split(',')])  # convert list comprehension to set for unique values
            for item in items:
                if '/' in item:  # if / is in the item, then it's a CIDR notation network
                    network = ipa.ip_network(item, strict=False)
                    for host in network.hosts():
                        target_queue.put((host, ports))  # put each IP of the network into the target queue
                else:
                    try:
                        target_queue.put((ipa.ip_address(item), ports))
                    except ValueError:
                        # can't convert item into an IP, treat it as a hostname instead and pass it unchanged
                        target_queue.put((item, ports))
        else:
            # -f/--file was used
            lines = [ln.strip() for ln in open(args.file, 'r').readlines()]
            for line in lines:
                if ' ' in line:
                    host, ports = line.split(' ', 1)
                    if len(ports.strip()) == 0:
                        # the line contained spaces but nothing after, so use default ports instead
                        ports = args.ports
                else:
                    host = line
                    ports = args.ports
                ports = set([int(p) for p in ports.split(',')])  # convert list comprehension to set for unique values
                if '/' in host:
                    network = ipa.ip_network(host, strict=False)
                    for host in network.hosts():
                        target_queue.put((host, ports))
                else:
                    try:
                        target_queue.put((ipa.ip_address(host), ports))
                    except ValueError:
                        # probably a hostname
                        target_queue.put((host, ports))
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
        sys.exit(1)

    # create args.threads threads, start them and add them to the list
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=scan_host, args=(target_queue, result_queue, args))
        t.start()
        threads.append(t)

    dbthread = threading.Thread(target=record_result, args=(result_queue, args))
    dbthread.start()

    while True:
        try:
            # periodically check if the queue still contains targets and if the threads are still running
            time.sleep(0.5)
            if target_queue.empty() and True not in [t.is_alive() for t in threads]:
                # queue is empty and all threads are done, finish the dbthread, then exit
                # to finish the dbthread, write the kill command to the result_queue. The thread will read
                # this command, finish writing, close the DB file, then return.
                result_queue.put(killcmd)
                dbthread.join()
                sys.exit(0)

        except KeyboardInterrupt:
            # Ctrl+C was pressed: empty the queue and wait for the threads to finish
            # each thread will return once the queue is empty
            while not target_queue.empty():
                try:
                    target_queue.get(block=False)
                except queue.Empty:
                    pass
            for t in threads:
                t.join()
            result_queue.put(killcmd)
            dbthread.join()
            sys.exit(0)


if __name__ == '__main__':
    main()
