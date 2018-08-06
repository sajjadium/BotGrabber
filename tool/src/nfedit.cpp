#include <utility/netflow.h>

#include <stdio.h>

using namespace utility;

int main(int argc, char *argv[]) {
	char *netflow_binary = new char[NETFLOW_BINARY_SIZE];

	FILE *netflow_file = fopen(argv[1], "r+");
	fseek(netflow_file, 0, SEEK_END);
	int file_size = ftell(netflow_file);
	fseek(netflow_file, 0, SEEK_SET);

	for (int i = 0; i < file_size / NETFLOW_BINARY_SIZE; i++) {
		fread(netflow_binary, 1, NETFLOW_BINARY_SIZE, netflow_file);
		
		NetflowBinaryOld *nfbin_old = (NetflowBinaryOld *)netflow_binary;
		NetflowBinary nfbin;
		nfbin.start_time = nfbin_old->start_time;
		nfbin.end_time = nfbin_old->end_time;
		nfbin.proto = nfbin_old->proto;
		nfbin.src_ip = nfbin_old->src_ip;
		nfbin.dst_ip = nfbin_old->dst_ip;
		nfbin.src_port = nfbin_old->src_port;
		nfbin.dst_port = nfbin_old->dst_port;
		nfbin.pkts_sent = nfbin_old->pkts_sent;
		nfbin.pkts_recv = nfbin_old->pkts_recv;
		nfbin.bytes_sent = nfbin_old->bytes_sent;
		nfbin.bytes_recv = nfbin_old->bytes_recv;

		fseek(netflow_file, -NETFLOW_BINARY_SIZE, SEEK_CUR);
		fwrite(&nfbin, 1, NETFLOW_BINARY_SIZE, netflow_file);
	}
	fclose(netflow_file);

	delete[] netflow_binary;

	return 0;
}

