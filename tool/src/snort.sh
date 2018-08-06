#!/bin/sh

snort -c /etc/snort/snort.conf --pcap-dir /share/botnet/it_fulldump/ 'not net 224.0.0.0/4'

