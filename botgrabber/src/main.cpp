#include "botgrabber.h"

char *DB_FILENAME;
char *SCAN_FILENAME;
char *OUTPUT_FILENAME;
char *PCAP_FOLDER;
char *PCAP_FILTER_EXPR;
double LEVEL_ONE_ERROR;
double LEVEL_TWO_ERROR;
unsigned int TIMEWINDOW_SIZE;
unsigned int MAX_NUM_TIMEWINDOW;
double CORRELATION_THRESHOLD;
double MAX_TW_SCORE;
double BOT_THRESHOLD;
double BULKY_THRESHOLD;

set<int> SMTP_PORTS;
deque<TimeWindow *> timewindow_list;
SqliteDB *sqlite_db;
deque<Netflow *> netflow_list;
deque<Scan *> scan_list;
map<Netflow *, Instance *> netflow_level_one_feature_table;
map<Netflow *, Instance *> netflow_level_two_feature_table;
deque<Regex *> white_list;
HostTable host_table;

double BASE_TIME = -1;
double TIMEWINDOW_START;
double TIMEWINDOW_END;
unsigned int TIMEWINDOW_ID = 0;

FILE *scan_file = NULL, *output_file = NULL;

Scan *readScan() {
	Scan *scan = new Scan;
	if (fread(scan, sizeof(Scan), 1, scan_file) != 1) {
		delete scan;
		scan = NULL;
	}

	return scan;
}

void loadConfig() {
	FILE *cfg_file = fopen("config.cfg", "r");

	char *line;
	while ((line = readline(cfg_file)) != NULL) {
		if (line[0] == '#') {
			delete[] line;
			continue;
		}

		char *name = strtok(line, "=");
		char *value = strtok(NULL, "=");

		if (name == NULL || value == NULL) {
			delete[] line;
			continue;
		}

		if (strcmp(name, "DB_FILENAME") == 0)
			DB_FILENAME = strclone(value);
		else if (strcmp(name, "SCAN_FILENAME") == 0)
			SCAN_FILENAME = strclone(value);
		else if (strcmp(name, "OUTPUT_FILENAME") == 0)
			OUTPUT_FILENAME = strclone(value);
		else if (strcmp(name, "PCAP_FOLDER") == 0)
			PCAP_FOLDER = strclone(value);
		else if (strcmp(name, "PCAP_FILTER_EXPR") == 0)
			PCAP_FILTER_EXPR = strclone(value);
		else if (strcmp(name, "LEVEL_ONE_ERROR") == 0)
			LEVEL_ONE_ERROR = str2double(value);
		else if (strcmp(name, "LEVEL_TWO_ERROR") == 0)
			LEVEL_TWO_ERROR = str2double(value);
		else if (strcmp(name, "TIMEWINDOW_SIZE") == 0)
			TIMEWINDOW_SIZE = str2int(value);
		else if (strcmp(name, "MAX_NUM_TIMEWINDOW") == 0)
			MAX_NUM_TIMEWINDOW = str2int(value);
		else if (strcmp(name, "CORRELATION_THRESHOLD") == 0)
			CORRELATION_THRESHOLD = str2double(value);
		 else if (strcmp(name, "BOT_THRESHOLD") == 0)
			BOT_THRESHOLD = str2double(value);
		else if (strcmp(name, "BULKY_THRESHOLD") == 0)
			BULKY_THRESHOLD = str2double(value);
		else if (strcmp(name, "MAX_TW_SCORE") == 0)
			MAX_TW_SCORE = str2double(value);

		delete[] line;
	}

	print("--------- Parameters ----------");
	printf("DB_FILENAME = %s\n", DB_FILENAME);
	printf("SCAN_FILENAME = %s\n", SCAN_FILENAME);
	printf("OUTPUT_FILENAME = %s\n", OUTPUT_FILENAME);
	printf("PCAP_FOLDER = %s\n", PCAP_FOLDER);
	printf("PCAP_FILTER_EXPR = %s\n", PCAP_FILTER_EXPR);
	printf("LEVEL_ONE_ERROR = %f\n", LEVEL_ONE_ERROR);
	printf("LEVEL_TWO_ERROR = %f\n", LEVEL_TWO_ERROR);
	printf("TIMEWINDOW_SIZE = %d\n", TIMEWINDOW_SIZE);
	printf("MAX_NUM_TIMEWINDOW = %d\n", MAX_NUM_TIMEWINDOW);
	printf("CORRELATION_THRESHOLD = %f\n", CORRELATION_THRESHOLD);
	printf("MAX_TW_SCORE = %f\n", MAX_TW_SCORE);
	printf("BOT_THRESHOLD = %f\n", BOT_THRESHOLD);
	print("");
}

bool initial() {
	loadConfig();
	bool res = true;

	scan_file = fopen(SCAN_FILENAME, "r");
//	output_file = fopen(OUTPUT_FILENAME, "w");

	sqlite_db = new SqliteDB(DB_FILENAME);

	sqlite_db->open();

	sqlite_db->executeUpdate("DROP TABLE IF EXISTS ip_name");
	sqlite_db->executeUpdate("DROP TABLE IF EXISTS scores");
	sqlite_db->executeUpdate("DROP TABLE IF EXISTS correlations");
	sqlite_db->executeUpdate("DROP TABLE IF EXISTS netflow_clusters");
	sqlite_db->executeUpdate("DROP TABLE IF EXISTS scan_clusters");

	sqlite_db->executeUpdate("CREATE TABLE IF NOT EXISTS ip_name (ip VARCHAR(16), name VARCHAR(255))");
	sqlite_db->executeUpdate("CREATE TABLE IF NOT EXISTS scores (ip VARCHAR(16), tw_id INT, score DOUBLE)");
	sqlite_db->executeUpdate("CREATE TABLE IF NOT EXISTS correlations (ip VARCHAR(16), tw_id INT, cor_tw_id INT, c_id INT, cor_c_id INT)");
//	sqlite_db->executeUpdate("CREATE TABLE IF NOT EXISTS clusters (tw_id INT, c_id INT, proto TINYINT, start_time FLOAT, end_time FLOAT, duration FLOAT, src_ip VARCHAR(16), src_port INT, dst_ip VARCHAR(16), dst_port INT, pkts_sent FLOAT, bytes_sent FLOAT, bpp_sent FLOAT, pkts_recv FLOAT, bytes_recv FLOAT, bpp_recv FLOAT)");
	sqlite_db->executeUpdate("CREATE TABLE IF NOT EXISTS netflow_clusters (tw_id INT, c_id INT, proto TINYINT, start_time FLOAT, end_time FLOAT, duration FLOAT, src_ip VARCHAR(16), src_port INT, dst_ip VARCHAR(16), dst_port INT)");

	sqlite_db->executeUpdate("CREATE TABLE IF NOT EXISTS scan_clusters (tw_id INT, c_id INT, time_stamp FLOAT, type INT, src_ip VARCHAR(16), dst_ip VARCHAR(16))");

	sqlite_db->executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS ip_name_index ON ip_name (ip, name)");

	print("---------- White List ----------");
	char pattern[100];
	FILE *wl_file = fopen("white_list.txt", "r");
	char *error;
	int error_offset;
	while (fgets(pattern, sizeof(pattern), wl_file) != NULL) {
		pattern[strlen(pattern) - 1] = 0;
		if (strlen(pattern) == 0 || pattern[0] == '#')
			continue;

		Regex *regex = new Regex(pattern);
		if (!regex->compile()) {
			delete regex;
			break;
		}

		printf("%s\n", regex->pattern);

		white_list.push_back(regex);
	}
	fclose(wl_file);
	print("");

	// initial smtp ports
	SMTP_PORTS.insert(25);
	SMTP_PORTS.insert(465);
	SMTP_PORTS.insert(587);

	return res;
}

void cleanup() {
	for (int i = 0; i < timewindow_list.size(); i++)
		if (timewindow_list[i] != NULL)
			delete timewindow_list[i];

	fclose(scan_file);
//	fclose(output_file);

	for (int i = 0; i < white_list.size(); i++)
		delete white_list[i];

	for (HostTable::iterator it = host_table.begin(); it != host_table.end(); it++)
		delete it->second;

	delete sqlite_db;
}

void c2Engine() {
	TimeWindow *time_window = new TimeWindow();

	char temp[200];

	createLevelOneFeatures(&netflow_list);
	createLevelTwoFeatures(&netflow_list);

	// flow level clustering
	deque<NetflowCluster *> *level_one_netflow_cluster_list = clustering(&netflow_list, netflow_level_one_feature_table, Distance::euclidean, LEVEL_ONE_ERROR);

//	for (int i = 0; i < level_one_netflow_cluster_list->size(); i++)
//		if (level_one_netflow_cluster_list->at(i)->src_ips->size() == 1)
//			delete level_one_netflow_cluster_list->at(i);
//		else
//			time_window->add(level_one_netflow_cluster_list->at(i));

	// level two clustering
	for (int i = 0; i < level_one_netflow_cluster_list->size(); i++) {
		deque<NetflowCluster *> *level_two_netflow_cluster_list = clustering(level_one_netflow_cluster_list->at(i)->netflow_list, netflow_level_two_feature_table, Distance::manhattan, LEVEL_TWO_ERROR);

		for (int j = 0; j < level_two_netflow_cluster_list->size(); j++) {
			if (level_two_netflow_cluster_list->at(j)->src_ips->size() < 2) {
				delete level_two_netflow_cluster_list->at(j);
				continue;
			}

			time_window->add(level_two_netflow_cluster_list->at(j));
		}

		delete level_two_netflow_cluster_list;
		delete level_one_netflow_cluster_list->at(i);
	}

	delete level_one_netflow_cluster_list;

	// print clusters
	for (int i = 0; i < time_window->ncSize(); i++) {
		NetflowCluster *netflow_cluster = time_window->getNC(i);
//		deque<double *> *netflow_features_list = netflow_cluster->netflowFeatures(netflow_level_one_feature_table, LEVEL_ONE_NUM_OF_FEATURES);
//		normalize(netflow_features_list, LEVEL_ONE_NUM_OF_FEATURES);

//		sprintf(temp, "\tCluster %d:", i);
//		print(temp);

		for (int j = 0; j < netflow_cluster->size(); j++) {
			Netflow *netflow = netflow_cluster->get(j);
//			double *netflow_features = netflow_features_list->at(j);

//			sprintf(temp, "\t\t%s", netflow->toString(BASE_TIME, TIMEWINDOW_START, TIMEWINDOW_END).c_str());
/*
			sprintf(temp, "\t\t%u %.6f %.6f %.6f %s:%u -> %s:%u %f %f %f %f %f %f",
					netflow->is_completed,
					netflow->start_time - BASE_TIME,
					netflow->end_time - BASE_TIME,
					netflow->getDuration(TIMEWINDOW_START, TIMEWINDOW_END),
					ip2str(netflow->conn->src_ip).c_str(),
					netflow->conn->src_port,
					ip2str(netflow->conn->dst_ip).c_str(),
					netflow->conn->dst_port,
					netflow_features[0],
					netflow_features[1],
					netflow_features[2],
					netflow_features[3],
					netflow_features[4],
					netflow_features[5]);

			print(temp);

			sprintf(temp, "INSERT INTO clusters VALUES(%d, %d, %d, %f, %f, %f, '%s', %d, '%s', %d, %f, %f, %f, %f, %f, %f)",
					TIMEWINDOW_ID, i,
					netflow->is_completed,
					netflow->start_time - BASE_TIME,
					netflow->end_time - BASE_TIME,
					netflow->getDuration(TIMEWINDOW_START, TIMEWINDOW_END),
					ip2str(netflow->conn->src_ip).c_str(),
					netflow->conn->src_port,
					ip2str(netflow->conn->dst_ip).c_str(),
					netflow->conn->dst_port,
					netflow_features[0],
					netflow_features[1],
					netflow_features[2],
					netflow_features[3],
					netflow_features[4],
					netflow_features[5]);
*/
			sprintf(temp, "INSERT INTO netflow_clusters VALUES(%u, %u, %u, %f, %f, %f, '%s', %u, '%s', %u)",
					TIMEWINDOW_ID, i,
					netflow->conn->proto,
					netflow->start_time - BASE_TIME,
					netflow->end_time - BASE_TIME,
					netflow->getDuration(TIMEWINDOW_START, TIMEWINDOW_END),
					ip2str(netflow->conn->src_ip).c_str(),
					netflow->conn->src_port,
					ip2str(netflow->conn->dst_ip).c_str(),
					netflow->conn->dst_port);
			sqlite_db->executeUpdate(temp);
		}
/*
		// free feature list
		for (int j = 0; j < netflow_features_list->size(); j++)
			delete[] netflow_features_list->at(j);
		delete netflow_features_list;
*/	}

	// cluster scan alerts
	map<int, ScanCluster *> scan_clusters;
	for (int i = 0; i < scan_list.size(); i++) {
		if (scan_clusters.count(scan_list[i]->type) == 0)
			scan_clusters.insert(pair<int, ScanCluster *>(scan_list[i]->type, new ScanCluster()));

		scan_clusters[scan_list[i]->type]->add(scan_list[i]);
	}

	for (map<int, ScanCluster *>::iterator it = scan_clusters.begin(); it != scan_clusters.end(); it++)
		if (it->second->size() > 1) {
			for (int i = 0; i < it->second->size(); i++) {
				sprintf(temp, "INSERT INTO scan_clusters VALUES(%u, %u, %f, %u, '%s', '%s')",
						TIMEWINDOW_ID, i,
						it->second->get(i)->time_stamp,
						it->second->get(i)->type,
						ip2str(it->second->get(i)->src_ip).c_str(),
						ip2str(it->second->get(i)->dst_ip).c_str());
				sqlite_db->executeUpdate(temp);
			}

			time_window->add(it->second);
		} else
			delete it->second;

	// create new time window
	timewindow_list.push_back(time_window);
	if (timewindow_list.size() > MAX_NUM_TIMEWINDOW  + 1) {
		delete timewindow_list[timewindow_list.size() - 5];
		timewindow_list[timewindow_list.size() - 5] = NULL;
	}
/*
	// print cluster ips
	for (int i = 0; i < timewindow_list[TIMEWINDOW_ID]->size(); i++) {
		Cluster *cluster = timewindow_list[TIMEWINDOW_ID]->getC(i);
		sprintf(temp, "\tCluster %d:", i);
		print(temp);

		for (set<unsigned int>::iterator it = cluster->src_ips->begin(); it != cluster->src_ips->end(); it++) {
			sprintf(temp, "\t\t%s", ip2str(*it).c_str());
			print(temp);
		}
	}
*/
	// correlate clusters (intra & inter)
	correlation();
}

bool checkValidNetflow(const Netflow *netflow) {
	// No data
	if (Netflow::getBytes(netflow->pkts_stats_sent, TIMEWINDOW_START, TIMEWINDOW_END) == 0 &&
		Netflow::getBytes(netflow->pkts_stats_recv, TIMEWINDOW_START, TIMEWINDOW_END) == 0)
		return false;

	// internal to internal && external to internal
	if (!((netflow->conn->src_ip & str2ip("255.255.0.0")) == str2ip("192.168.0.0") &&
		(netflow->conn->dst_ip & str2ip("255.255.0.0")) != str2ip("192.168.0.0")))
		return false;

	// bulky
	if (Netflow::getBytes(netflow->pkts_stats_sent, TIMEWINDOW_START, TIMEWINDOW_END) > BULKY_THRESHOLD ||
		Netflow::getBytes(netflow->pkts_stats_recv, TIMEWINDOW_START, TIMEWINDOW_END) > BULKY_THRESHOLD)
		return false;

	// whilte list
	if (SMTP_PORTS.count(netflow->conn->dst_port) == 0) {
		char cmd[200];
		sprintf(cmd, "SELECT name FROM ip_name WHERE ip = '%s'", ip2str(netflow->conn->dst_ip).c_str());
		ResultSet *rs = sqlite_db->executeSelect(cmd);
		for (int i = 0; i < rs->size(); i++) {
			char *name = (*rs->at(i))["name"];
			for (int j = 0; j < white_list.size(); j++)
				if (white_list[j]->match(name)) {
					SqliteDB::freeResultSet(rs);
					return false;
				}
		}

		SqliteDB::freeResultSet(rs);
	}

	return true;
}

int main(int argc, char *argv[]) {
	initial();

	time_t start_time = time(NULL);

	int total_netflows = 0, total_scans = 0;

	char temp[200];

	NetflowGenerator netflow_generator;

	PcapStream pcap_stream(PCAP_FOLDER, PCAP_FILTER_EXPR, -1);
	if (!pcap_stream.open())
		return 1;

	print("---------- Start ---------");
	while (true) {
		Packet *packet = pcap_stream.nextPacket();

		if (packet == NULL)
			break;

		if (packet->decode()) {
			if (packet->udp_hdr != NULL && net2host(packet->udp_hdr->src_port) == 53)
				updateIp2NameTable(packet);

			if (BASE_TIME == -1) {
				BASE_TIME = packet->getTime();
				TIMEWINDOW_START = BASE_TIME;
				TIMEWINDOW_END = TIMEWINDOW_START + TIMEWINDOW_SIZE;
			}

			if (packet->getTime() >= TIMEWINDOW_END) {
				// timeout netflows
				deque<Netflow *> *timeout_netflow_list = netflow_generator.getTimeoutNetflows();
				netflow_list.insert(netflow_list.end(), timeout_netflow_list->begin(), timeout_netflow_list->end());
				delete timeout_netflow_list;

				// flush netflows
				deque<Netflow *> *flushed_netflow_list = netflow_generator.flush();
				netflow_list.insert(netflow_list.end(), flushed_netflow_list->begin(), flushed_netflow_list->end());
				delete flushed_netflow_list;

				// remove netflows that aren't valid or in time window
				int num_of_filter_netflows = 0;
				deque<Netflow *>::iterator it = netflow_list.begin();
				while (it != netflow_list.end()) {
					Netflow *netflow = *it;

					bool is_valid = true;

					if (netflow->end_time < TIMEWINDOW_START)
						is_valid = false;

					if (!(is_valid = checkValidNetflow(netflow)))
						num_of_filter_netflows++;

					if (!is_valid) {
						it = netflow_list.erase(it);
						if (netflow->is_completed)
							delete netflow;
					} else
						it++;
				}

				// read scans
				while (true) {
					Scan *scan = readScan();
					if (scan == NULL)
						break;

					if (scan->time_stamp < TIMEWINDOW_END)
						if ((scan->src_ip & str2ip("255.255.0.0")) == str2ip("192.168.0.0"))
							scan_list.push_back(scan);
						else
							delete scan;
					else {
						fseek(scan_file, -sizeof(Scan), SEEK_CUR);
						delete scan;
						break;
					}
				}

				sprintf(temp, "Time window %d, [%.2f, %.2f)", TIMEWINDOW_ID, TIMEWINDOW_START - BASE_TIME, TIMEWINDOW_END - BASE_TIME);
				print(temp);

//				sprintf(temp, "\tNetflows = %d, Filtered Netflows = %d, Scans = %d", (int)netflow_list.size(), num_of_filter_netflows, (int)scan_list.size());
//				print(temp);
				/*
				   print("\t------------------------------------------------------------------------------------------------------------------------------");

				   sort(netflow_list.begin(), netflow_list.end(), NetflowCompare());

				   for (int i = 0; i < netflow_list.size(); i++) {
				   sprintf(temp, "\t%s", netflow_list[i]->toString(BASE_TIME, TIMEWINDOW_START, TIMEWINDOW_END).c_str());
				   print(temp);
				   }

				   print("\t------------------------------------------------------------------------------------------------------------------------------");
				 */
				c2Engine();

				total_netflows += netflow_list.size();
				total_scans += scan_list.size();

				TIMEWINDOW_ID++;

				TIMEWINDOW_START += TIMEWINDOW_SIZE;
				TIMEWINDOW_END += TIMEWINDOW_SIZE;

				// free feature tables
				for (int i = 0; i < netflow_list.size(); i++) {
					delete netflow_level_one_feature_table[netflow_list[i]];
					delete netflow_level_two_feature_table[netflow_list[i]];
				}
				netflow_level_one_feature_table.clear();
				netflow_level_two_feature_table.clear();

				// free completed netflows
				for (int i = 0; i < netflow_list.size(); i++)
					if (netflow_list[i]->is_completed)
						delete netflow_list[i];
				netflow_list.clear();

				// free scans
				for (int i = 0; i < scan_list.size(); i++)
					delete scan_list[i];
				scan_list.clear();
			}

			// read netflows
			if (packet->tcp_hdr != NULL) {
				Netflow *netflow = netflow_generator.process(packet);
				if (netflow != NULL)
					netflow_list.push_back(netflow);
			}
		}

		delete packet;
	}

	sprintf(temp, "Run Time = %ld, Total Netflows = %d, Total Scans = %d", time(NULL) - start_time, total_netflows, total_scans);
	print(temp);

	cleanup();

	return 0;
}

