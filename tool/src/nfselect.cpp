#include <utility/netflow.h>
#include <utility/common.h>

#include <stdio.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	printf("%d\n", sizeof(fpos_t));
	return 0;
	char data[200];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		Netflow *netflow = Netflow::fromString(data);

		if (netflow->bytes_sent != 0 && netflow->bytes_recv != 0)
			printf("%s\n", netflow->toString().c_str());

		delete netflow;

//		if ((netflow->conn->src_ip == str2ip(argv[1]) && netflow->conn->dst_ip == str2ip(argv[2])) ||
//			(netflow->conn->dst_ip == str2ip(argv[1]) && netflow->conn->src_ip == str2ip(argv[2]))) {
//		}
	}

	return 0;
}

