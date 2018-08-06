#include <utility.h>
#include <pcap.h>

using namespace utility;

void processPacket(unsigned char *dumper, const struct pcap_pkthdr *pcap_header, const u_char *pcap_frame) {
	Packet *packet = new Packet(pcap_header, pcap_frame);
	if (packet->fix())
		packet->dump(dumper);

	delete packet;
}

int main (int argc, char **argv) {
	pcap_t *pcap = NULL;
	pcap_dumper_t *dumper = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((pcap = pcap_open_offline("-", errbuf)) == NULL) {
		fprintf(stderr, "Error Input: %s\n", errbuf);
		return -1;
	}

	if ((dumper = pcap_dump_open(pcap, "-")) == NULL) {
		fprintf(stderr, "Error Dumper: %s\n", errbuf);
		return -1;
	}

	pcap_loop(pcap, -1, processPacket, (unsigned char *)dumper);

	pcap_close(pcap);

	pcap_dump_flush(dumper);
	pcap_dump_close(dumper);

	return 0;
}

