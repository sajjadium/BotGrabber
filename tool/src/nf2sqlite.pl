#!/usr/bin/perl

my $nfid = 0;

while ($line = <STDIN>) {
	chomp($line);
	@netflow= split(/[\s|(|)|:|\-|>]+/, $line);
	($start_tim, $end_time, $duration, $proto, $src_ip, $src_port, $pkts_sent, $bytes_sent, $dst_ip, $dst_port, $pkts_recv, $bytes_rec) = @netflow;
	print "$nfid|$start_tim|$end_time|$proto|$src_ip|$src_port|$pkts_sent|$bytes_sent|$dst_ip|$dst_port|$pkts_recv|$bytes_rec\n";
	$nfid = $nfid + 1;
}

