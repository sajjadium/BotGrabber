#!/bin/sh

./dispatch.exe /home/r00t/botnet/it_fulldump | snort -c /etc/snort/snort.conf -r - 2> /dev/null | ./scan2bin.exe > /home/r00t/botnet/sbu_scan.bin 2> /home/r00t/botnet/sbu_scan.txt

