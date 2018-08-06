#include <utility/netflow.h>

#include <utility/common.h>

#include <stdio.h>
#include <stdlib.h>

using namespace utility;
using namespace std;

int main(int argc, char *argv[]) {
	while (true) {
		Netflow *netflow = Netflow::fromBinary(stdin);
		fprintf(stdout, "%s\n", netflow->toString().c_str());
		fflush(stdout);

		delete netflow;
	}

	return 0;
}

