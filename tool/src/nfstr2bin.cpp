#include <utility/netflow.h>

#include <stdio.h>

using namespace utility;

int main(int argc, char *argv[]) {
	char data[200];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		Netflow *netflow = Netflow::fromString(data);
		char *netflow_bin = netflow->toBinary();
		fwrite(netflow_bin, 1, NETFLOW_BINARY_SIZE, stdout);
		fflush(stdout);
		delete netflow;
		delete[] netflow_bin;
	}

	return 0;
}

