#include <utility/packet.h>
#include <utility/netflow.h>
#include <utility/pcap.h>

#include <stdio.h>
#include <time.h>

#include <deque>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	int flow_count = 0;

	time_t ft = time(NULL);

	NetflowGenerator netflow_generator;
	PcapStream pcap_stream(argv[1], "ip and tcp and (not net 224.0.0.0/4)", -1);

	if (!pcap_stream.open())
		return 1;

	while (true) {
		Packet *packet = pcap_stream.nextPacket();
		if (packet == NULL)
			break;

		if (packet->decode()) {
			Netflow *netflow = netflow_generator.process(packet);
			if (netflow != NULL) {
				flow_count ++;
				delete netflow;
			}
		}

		delete packet;
	}

	pcap_stream.close();

	deque<Netflow *> *netflow_list = netflow_generator.flush();

	printf("Flow Count = %d\n", (int)(flow_count + netflow_list->size()));

	return 0;
}

