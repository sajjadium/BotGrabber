#!/usr/bin/perl

my $scan_id = 0;

while ($line = <STDIN>) {
	chomp($line);
	@scan = split(/[\s]+/, $line);
	($time_stamp, $src_ip, $dst_ip) = @scan;
	print "$scan_id|$time_stamp|$src_ip|$dst_ip\n";
	$scan_id = $scan_id + 1;
}

