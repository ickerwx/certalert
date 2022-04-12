# certalert
Check host certificates and get an alert when a certificate is about to expire or has expired.

```
./certalert -h                                       
usage: certalert [-h] (-i HOSTS | -f FILE) [-p PORTS] [-d DBFILE] [-g IGNOREFILE] [-l] [-k] [-y DAYS] [-t THREADS] [-to TIMEOUT] [-v]

Check sites and servers for expiring/expired TLS certificates

options:
  -h, --help            show this help message and exit
  -i HOSTS, --ip HOSTS  comma-separated list of hostnames, IP addresses or CIDR networks (e.g. localhost,127.0.0.1,fe80::,1.2.3.0/24)
  -f FILE, --file FILE  file containing host port1,port2,... lines, one line per host (see README)
  -p PORTS, --ports PORTS
                        comma-separated list of ports (default: 443,636,993,995,8443)
  -d DBFILE, --db DBFILE
  -g IGNOREFILE, --ignore IGNOREFILE
                        File with hosts that should be ignored, one host per line (default: None)
  -l, --splunk          Send an event to Splunk using the HTTP Event Collector (see splunk.json) (default: False)
  -k, --insecure        Disable certificate checks when sending data to splunk. (default: False)
  -y DAYS, --days DAYS  days until expiry date (default: 7)
  -t THREADS, --threads THREADS
                        set number of threads (default: 5)
  -to TIMEOUT, --timeout TIMEOUT
                        socket timeout (default: 0.5)
  -v, --verbose
```

You can pass multiple IP addresses, hostnames, networks and ports by separating them with a comma:

```
-i 127.0.0.1,127.0.0.2,localhost,127.1.2.0/24 -p 1,2,3,4,5
```

You can also query IPv6 addresses, and query a mix of IPv6 and IPv4 addresses. The default number of threads is 5, this seems to be more than enough on a LAN.

## Input file format

```
$ cat examplefile
1.1.1.1
2.2.2.2 22
3.3.3.3 33,333
4.4.4.4 44,444,4444
5.5.5.5/24
localhost
6.6.6.6/28 66,666,6666
anotherhost.localnet
example.net 443
```

Don't specify /32 as a subnet mask, this will not work.
If you don't specify ports in the file, then the program will use either the default ports or whatever you specify with `-p`.

## Storing results
The script will store certs that have expired or are about to expire in an sqlite database. The stored data is
- `date`: the time and day of the scan
- `host`: scanned host
- `port`: scanned port
- `certificate`: PEM encoded host certificate
- `fingerprint`: SHA256 fingerpring of the certificate
- `expired`: 1 if cert has expired, 0 if not (meaning it will expire soon)
- `expirydate`: the 'not after' field of the certificate

### Splunk HEC
You can optionally send the results to Splunk using an HTTP Event Collector. Edit the file `splunk.json`, add the URL, the token and edit the sourcetype. The token in this repo is a test token for a local docker container, please don't open an issue for this, thanks.
