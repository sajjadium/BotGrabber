#include <utility/pcap.h>
#include <utility/packet.h>

using namespace utility;

int main(int argc, char *argv[]) {
	PcapStream pcap_stream(argv[1], "", -1);
	if (!pcap_stream.open())
		return 1;

	PcapDump pcap_dump(stdout);
	if (!pcap_dump.open())
		return 1;

	while (true) {
		Packet *packet = pcap_stream.nextPacket();

		if (packet == NULL)
			break;

		pcap_dump.dump(packet);

		delete packet;
	}

	pcap_dump.close();
	pcap_stream.close();

	return 0;
}

