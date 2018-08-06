#include <utility/pcap.h>
#include <utility/packet.h>
#include <utility/common.h>

using namespace utility;

int main(int argc, char *argv[]) {
	Pcap pcap(argv[1], "", -1);
	if (!pcap.openOffline())
		return 1;

	PcapDump pcap_dump(argv[2]);
	if (!pcap_dump.open())
		return 2;

	while (true) {
		Packet *packet = pcap.nextPacket();
		if (packet == NULL)
			break;

		if (packet->decode() && packet->ip4_hdr != NULL) {
			if (packet->ip4_hdr->src_ip == host2net(str2ip(argv[3]))) {
				packet->ip4_hdr->src_ip = host2net(str2ip(argv[4]));
			} else if (packet->ip4_hdr->dst_ip == host2net(str2ip(argv[3]))) {
				packet->ip4_hdr->dst_ip = host2net(str2ip(argv[4]));
			}
		}

		pcap_dump.dump(packet);

		delete packet;
	}

	pcap.close();
	pcap_dump.close();

	return 0;
}

