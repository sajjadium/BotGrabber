#include <utility/netflow.h>

#include <stdio.h>

using namespace utility;

int main(int argc, char *argv[]) {
	char *bin = new char[NETFLOW_BINARY_SIZE];
	FILE *tcp_file = fopen(argv[1], "w");
	FILE *udp_file = fopen(argv[2], "w");

	while (true) {
		if (fread(bin, 1, NETFLOW_BINARY_SIZE, stdin) != NETFLOW_BINARY_SIZE)
			break;

		NetflowBinary *netflow_bin = (NetflowBinary *)bin;
		if (netflow_bin->proto == 6) {
			fwrite(bin, 1, NETFLOW_BINARY_SIZE, tcp_file);
			fflush(tcp_file);
		} else if (netflow_bin->proto == 17) {
			fwrite(bin, 1, NETFLOW_BINARY_SIZE, udp_file);
			fflush(udp_file);
		} else
			fprintf(stderr, "Unknown = %u\n", netflow_bin->proto);
	}

	delete[] bin;
	fclose(tcp_file);
	fclose(udp_file);

	return 0;
}

