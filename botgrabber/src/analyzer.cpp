#include <utility/sqlitedb.h>
#include <utility/common.h>
#include <stdio.h>

using namespace utility;

void printCluster(SqliteDB *sqlite_db, const char *tw_id, const char *c_id, unsigned int ip) {
	printf("Time Window %s, Cluster %s\n", tw_id, c_id);

	char sql_cmd[400];
	sprintf(sql_cmd, "SELECT * FROM clusters WHERE tw_id = %s AND c_id = %s ORDER BY src_ip, src_port, dst_ip, dst_port;", tw_id, c_id);
	ResultSet *rs = sqlite_db->executeSelect(sql_cmd);
	for (int i = 0; i < rs->size(); i++) {
		DataRow *dr = rs->at(i);
		printf("\t %d (%s:%s)\t->\t(%s:%s)\t%.2f %.2f %.2f %.2f %.2f %.2f %.2f %.2f\n",
				str2int((*dr)["proto"]),
				ip2str(str2int((*dr)["src_ip"])).c_str(),
				(*dr)["src_port"],
				ip2str(str2int((*dr)["dst_ip"])).c_str(),
				(*dr)["dst_port"],
				str2double((*dr)["pkts_sent"]),
				str2double((*dr)["bytes_sent"]),
				str2double((*dr)["bps_sent"]),
				str2double((*dr)["bpp_sent"]),
				str2double((*dr)["pkts_recv"]),
				str2double((*dr)["bytes_recv"]),
				str2double((*dr)["bps_recv"]),
				str2double((*dr)["bpp_recv"]));
	}

	SqliteDB::freeResultSet(rs);
}

int main(int argc, char *argv[]) {
	SqliteDB sqlite_db("/share/botnet/it_botgraber.db");
	if (!sqlite_db.open())
		return 1;

	char sql_cmd[200];
	unsigned int ip = str2ip(argv[1]);
	sprintf(sql_cmd, "SELECT * FROM host_history WHERE ip = %d;", ip);

	ResultSet *rs = sqlite_db.executeSelect(sql_cmd);

	for (int i = 0; i < rs->size(); i++) {
		printf("-------------------------------------------\n");
		DataRow *dr = rs->at(i);
		printCluster(&sqlite_db, (*dr)["tw_id1"], (*dr)["c_id1"], ip);
		printCluster(&sqlite_db, (*dr)["tw_id2"], (*dr)["c_id2"], ip);
	}

	SqliteDB::freeResultSet(rs);
}

