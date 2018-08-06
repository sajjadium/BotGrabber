#include <utility/common.h>
#include <utility/pcap.h>
#include <utility/packet.h>

#include <set>

#include <stdio.h>
#include <string.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	return 0;
	const char *dir_path = "/share/hdrdump/";
	deque<string> *files = listDirectory(dir_path);
//	unsigned int netmask = str2ip("255.255.255.128");
//	unsigned int net = str2ip("194.225.73.0");
//	set<unsigned int> lan_ips;
//	PcapDump pcap_dump(stdout);

//	double first_time = -1, last_time;
	double first_time = -1;

	for (int i = 0; i < files->size(); i++) {
		char file_path[200];
		strcpy(file_path, dir_path);
		strcat(file_path, files->at(i).c_str());
//		fprintf(stderr, "%s\n", file_path);

		Pcap pcap;
		pcap.openOffline(file_path);
		struct pcap_pkthdr header;
		char *frame;

		while (true) {
			frame = pcap.next(&header);
			if (frame == NULL)
				break;

			Packet packet(&header, frame);

			if (packet.decode())
				pcap_dump.dump(&packet);

//			sleep(1000);

//			if (first_time == -1)
//				first_time = packet.getTime();

//			last_time = packet.getTime();

//			unsigned int src_ip = net2host(packet.ip4_hdr->src_ip);
//			if ((src_ip & netmask) == net)
//				printf("%s\n", ip2str(src_ip).c_str());
//				lan_ips.insert(src_ip);
		}

		pcap.close();
	}

//	pcap_dump.close();

	delete files;
	pcap_dump.close();

//	printf("%f\n", (last_time - first_time) / 60);

//	for (set<unsigned int>::iterator it = lan_ips.begin(); it != lan_ips.end(); it++)
//		printf("%s\n", ip2str(*it).c_str());

	return 0;
}

