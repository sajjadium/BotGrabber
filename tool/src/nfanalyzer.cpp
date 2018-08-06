#include <utility/common.h>
#include <utility/pcap.h>
#include <utility/packet.h>
#include <utility/netflow.h>

#include <set>

#include <stdio.h>
#include <string.h>
#include <time.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	unsigned int netmask = str2ip("255.255.255.128");
	unsigned int net = str2ip("194.225.73.0");
	char data[200];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		Netflow *netflow = Netflow::fromString(data);

		unsigned int src_ip = netflow->conn->src_ip;
		if (/*(src_ip & netmask) == net &&*/ netflow->conn->dst_port == 25 || netflow->conn->src_port == 25) {
			fprintf(stdout, "%s", data);
			fflush(stdout);
		}

		delete netflow;
	}

	return 0;
}

