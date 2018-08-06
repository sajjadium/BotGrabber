#include <utility/netflow.h>

#include <utility/common.h>

#include <stdio.h>
#include <stdlib.h>

using namespace utility;
using namespace std;

struct Scan {
	double time_stamp;
	int type;
	unsigned int src_ip;
	unsigned int dst_ip;
} __attribute__((packed));

int main(int argc, char *argv[]) {
	Scan scan;

	while (true) {
		if (fread(&scan, sizeof(Scan), 1, stdin) != 1)
			break;

		fprintf(stdout, "%.6f %d %15s %15s\n", scan.time_stamp, scan.type, ip2str(scan.src_ip).c_str(), ip2str(scan.dst_ip).c_str());
		fflush(stdout);
	}

	return 0;
}

