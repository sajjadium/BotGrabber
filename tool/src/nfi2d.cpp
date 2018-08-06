#include <utility/netflow.h>
#include <utility/common.h>

#include <stdio.h>
#include <stdlib.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	char data[200];

	while (fgets(data, sizeof(data), stdin) != NULL) {
		Netflow *netflow = Netflow::fromString(data);
		printf("%s\n", netflow->toString().c_str());
		delete netflow;
	}

	return 0;
}

