#!/usr/bin/perl

while ($line = <STDIN>) {
	chomp($line);
	@netflow= split(/[\s|(|)|:|\-|>]+/, $line);
	($start_tim, $end_time, $duration, $proto, $src_ip, $src_port, $pkts_sent, $bytes_sent, $dst_ip, $dst_port, $pkts_recv, $bytes_rec) = @netflow;

	if ($dst_port == 25) {
		print "$line\n";
	}
}

