#include <stdio.h>
#include <pcap.h>
#include <deque>
#include <set>
#include <list>
#include <utility/common.h>
#include <utility/pcap.h>
#include <string.h>
#include <time.h>

using namespace std;
using namespace utility;

struct PcapPacket {
	double time_stamp;
	FILE *file;
	long int pos;
};

class PcapPacketCompare {
	public:
		bool operator()(const PcapPacket *pp1, const PcapPacket *pp2) const {
			return pp1->time_stamp < pp2->time_stamp;
		}
};

int main(int argc, char *argv[]) {
	time_t start_time = time(NULL);

	multiset<PcapPacket *, PcapPacketCompare> pkts;

	deque<char *> *filenames = listDirectory(argv[1]);
	deque<FILE *> files;
	for (int i = 0; i < filenames->size(); i++) {
		FILE *in_file = fopen(filenames->at(i), "r");
		if (in_file == NULL) {
			fprintf(stderr, "Can not open file\n");
			break;
		}

		files.push_back(in_file);

		fprintf(stderr, "%s\n", filenames->at(i));

		// read global header
		pcap_file_header global_hdr;
		fread(&global_hdr, sizeof(pcap_file_header), 1, in_file);

		// read packet
		while (true) {
			PcapPacket *pkt = new PcapPacket;
			pkt->file = in_file;
			pkt->pos = ftell(in_file);

			pcap_pkthdr header;
			if (fread(&header, sizeof(pcap_pkthdr), 1, in_file) != 1) {
				delete pkt;
				break;
			}

			pkt->time_stamp = pcapTime(&header);

			fseek(in_file, header.caplen, SEEK_CUR);

			pkts.insert(pkt);
		}
	}

	printf("Reading Time = %ld, Num. of Packets = %d\n", time(NULL) - start_time, pkts.size());

	start_time = time(NULL);

	PcapDump pcap_dump(argv[2]);
	if (!pcap_dump.open())
		return 1;

	pcap_pkthdr header;
	char frame[2000];

	multiset<PcapPacket *, PcapPacketCompare>::iterator it = pkts.begin();
	while (it != pkts.end()) {
		PcapPacket *pp = *it;

		fseek(pp->file, pp->pos, SEEK_SET);

		fread(&header, sizeof(pcap_pkthdr), 1, pp->file);
		fread(frame, 1, header.caplen, pp->file);

		pcap_dump.dump(&header, frame);

		pkts.erase(it++);
		delete pp;
	}

	pcap_dump.close();

	printf("Writing Time = %ld\n", time(NULL) - start_time);

	// free filenames and close files
	for (int i = 0; i < filenames->size(); i++) {
		delete[] filenames->at(i);
		fclose(files.at(i));
	}
	delete filenames;

	return 0;
}

