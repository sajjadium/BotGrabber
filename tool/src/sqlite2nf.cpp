#include <utility/netflow.h>
#include <string.h>
#include <stdio.h>

using namespace utility;

int main(int argc, char *argv[]) {
	char data[300];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		char *data_ = strchr(data, '|') + 1;
		Netflow *netflow = Netflow::fromString(data_);
		printf("%s\n", netflow->toString().c_str());
		fflush(stdout);
		delete netflow;
	}

	return 0;
}

