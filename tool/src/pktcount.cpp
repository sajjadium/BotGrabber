#include <utility/pcap.h>
#include <utility/packet.h>
#include <stdio.h>

using namespace utility;

int main(int argc, char *argv[]) {
	PcapStream pcap_stream(argv[1], "ip and (icmp or tcp or udp)", -1);

	if (!pcap_stream.open())
		return 1;

	unsigned int pkt_count = 0, icmp_count = 0, tcp_count = 0, udp_count = 0;
	double first_pkt_time = -1;
	double last_pkt_time = 0;

	while (true) {
		Packet *packet = pcap_stream.nextPacket();

		if (packet == NULL)
			break;

		if (first_pkt_time == -1)
			first_pkt_time = packet->getTime();

		last_pkt_time = packet->getTime();

		pkt_count ++;

		if (packet->decode()) {
			if (packet->icmp_hdr != NULL)
				icmp_count ++;
			else if (packet->tcp_hdr != NULL)
				tcp_count ++;
			else if (packet->udp_hdr != NULL)
				udp_count ++;
		}

		delete packet;
	}

	pcap_stream.close();

	printf("Total Pkts = %u, ICMP Pkts = %u, TCP Pkts = %u, UDP Pkts = %u, Duration = %f\n", pkt_count, icmp_count, tcp_count, udp_count, (last_pkt_time - first_pkt_time) / 3600.0);

	return 0;
}

