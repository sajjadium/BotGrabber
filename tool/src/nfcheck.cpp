#include <utility/netflow.h>

#include <utility/common.h>

#include <stdio.h>
#include <stdlib.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	char *bin = new char[NETFLOW_BINARY_SIZE];

	while (true) {
		if (fread(bin, 1, NETFLOW_BINARY_SIZE, stdin) != NETFLOW_BINARY_SIZE)
			break;

		Netflow *netflow = Netflow::fromBinary(bin);
		unsigned int bytes_sent = 0, bytes_recv = 0;
		for (int i = 0; i < 256; i++) {
			bytes_sent += netflow->ascii_count_sent[i];
			bytes_recv += netflow->ascii_count_recv[i];
		}

		if (netflow->bytes_sent != bytes_sent)
			printf("SENT: %s\n", netflow->toString().c_str());
		
		if (netflow->bytes_recv != bytes_recv)
			printf("RECV: %s\n", netflow->toString().c_str());

		fflush(stdout);

		delete netflow;
	}

	delete[] bin;

	return 0;
}

