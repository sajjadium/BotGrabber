#include <utility/netflow.h>
#include <utility/packet.h>

#include <deque>
#include <algorithm>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

using namespace utility;
using namespace std;

class NFCompare {
	public:
		bool operator()(const char *str1, const char *str2) const {
			NetflowBinary *netflow_bin1 = (NetflowBinary *)str1;
			NetflowBinary *netflow_bin2 = (NetflowBinary *)str2;

			if (netflow_bin1->start_time != netflow_bin2->start_time)
				return (netflow_bin1->start_time < netflow_bin2->start_time);
			else if (netflow_bin1->end_time != netflow_bin2->end_time)
				return (netflow_bin1->end_time < netflow_bin2->end_time);
			else if (netflow_bin1->proto != netflow_bin2->proto)
				return (netflow_bin1->proto < netflow_bin2->proto);
			else if (netflow_bin1->src_ip != netflow_bin2->src_ip)
				return (netflow_bin1->src_ip < netflow_bin2->src_ip);
			else if (netflow_bin1->dst_ip != netflow_bin2->dst_ip)
				return (netflow_bin1->dst_ip < netflow_bin2->dst_ip);
			else if (netflow_bin1->src_port != netflow_bin2->src_port)
				return (netflow_bin1->src_port < netflow_bin2->src_port);
			else if (netflow_bin1->dst_port != netflow_bin2->dst_port)
				return (netflow_bin1->dst_port < netflow_bin2->dst_port);
			else
				return false;
		}
};

int main(int argc, char *argv[]) {
	struct pcap_pkthdr *h;
	char *frame;
	Packet *packet = new Packet(h, frame);
	return 0;
	FILE *netflow_file = fopen(argv[1], "r");
	fseek(netflow_file, 0, SEEK_END);
	int file_size = ftell(netflow_file);
	fseek(netflow_file, 0, SEEK_SET);

	time_t time_ = time(NULL);

	deque<char *> netflow_list (file_size / NETFLOW_BINARY_SIZE, (char *)0);
	for (int i = 0; i < netflow_list.size(); i++) {
		char *netflow_binary = new char[NETFLOW_BINARY_SIZE];
		fread(netflow_binary, 1, NETFLOW_BINARY_SIZE, netflow_file);
		netflow_list[i] = netflow_binary;
	}
	fclose(netflow_file);

	fprintf(stderr, "Loading Completed in %ld seconds.\n", time(NULL) - time_);

	time_ = time(NULL);

	sort(netflow_list.begin(), netflow_list.end(), NFCompare());

	fprintf(stderr, "Sorting Completed in %ld seconds.\n", time(NULL) - time_);

	time_ = time(NULL);

	for (int i = 0; i < netflow_list.size(); i++) {
		fwrite(netflow_list[i], 1, NETFLOW_BINARY_SIZE, stdout);
		delete[] netflow_list[i];
	}

	fprintf(stderr, "Writing Completed in %ld seconds.\n", time(NULL) - time_);

	return 0;
}

