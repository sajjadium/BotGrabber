#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <utility/netflow.h>
#include <utility/common.h>
#include <utility/sqlitedb.h>

using namespace utility;

sig_atomic_t is_finished = 0;

void handler (int signal_number) {
	is_finished = 1;
}

int main(int argc, char *argv[]) {
	struct sigaction sa;
	memset (&sa, 0, sizeof (sa));
	sa.sa_handler = &handler;
	sigaction (SIGINT, &sa, NULL);

	SqliteDB sqlite_db(argv[1]);
	if (!sqlite_db.open())
		return 1;

	time_t start_time = time(NULL);
	int start_row, next_row;
	start_row = next_row = str2int(argv[2]);

	char data[200], cmd[200];
	for (int i = 0; i < start_row; i++)
		fgets(data, sizeof(data), stdin);

	while (is_finished == 0 && fgets(data, sizeof(data), stdin) != NULL) {
		Netflow *netflow = Netflow::fromString(data);
		sprintf(cmd, "INSERT INTO netflow VALUES(%u, %u, %u, '%s', %u, %u, %u, '%s', %u, %u, %u)", netflow->start_time,
																									netflow->end_time,
																									netflow->conn->proto,
																									ip2str(netflow->conn->src_ip).c_str(),
																									netflow->conn->src_port,
																									netflow->pkts_sent,
																									netflow->bytes_sent,
																									ip2str(netflow->conn->dst_ip).c_str(),
																									netflow->conn->dst_port,
																									netflow->pkts_recv,
																									netflow->bytes_recv);
		sqlite_db.executeUpdate(cmd);

		delete netflow;

		next_row++;
	}

	sqlite_db.close();

	char log[200];
	sprintf(log, "Elapsed Time = %ld, Total Rows = %d, Next Row = %d", time(NULL) - start_time, next_row - start_row, next_row);

	fprintf(stdout, "%s\n", log);
	fprintf(stderr, "%s\n", log);

	return 0;
}

