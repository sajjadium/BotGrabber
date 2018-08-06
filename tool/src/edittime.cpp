#include <utility/pcap.h>
#include <utility/packet.h>
#include <utility/common.h>

#include <stdio.h>

using namespace utility;

int main(int argc, char *argv[]) {
//	PcapStream pcap_stream(argv[1], "", -1);
	Pcap pcap_stream(argv[1], "", 1);
	PcapDump pcap_dump(argv[2]);

	if (!pcap_stream.openOffline())
		return 1;

	if (!pcap_dump.open())
		return 1;

	double first_pkt_time = -1;
	double start_time = str2double(argv[3]);

	while (true) {
		Packet *packet = pcap_stream.nextPacket();

		if (packet == NULL)
			break;

		printf("%ld\n", sizeof(struct timeval));

//		double old_time = packet->getTime();

//		if (first_pkt_time == -1)
//			first_pkt_time = old_time;

//		packet->setTime(start_time + old_time - first_pkt_time);

		pcap_dump.dump(packet);

		delete packet;
	}

	pcap_stream.close();
	pcap_dump.close();

	return 0;
}

