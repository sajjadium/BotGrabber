#include <utility/netflow.h>

#include <stdio.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	char data[200];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		Netflow *netflow = Netflow::fromString(data);
		if (netflow->bytes_sent != 0 && netflow->bytes_recv != 0)
			printf("%s\n", netflow->toString().c_str());
		delete netflow;
	}

	return 0;
}

