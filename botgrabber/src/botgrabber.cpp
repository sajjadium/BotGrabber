#include "botgrabber.h"

extern deque<deque<set<unsigned int> *> *> timewindow_list;
extern HostTable host_table;
extern FILE *output_file;
extern SqliteDB *sqlite_db;

set<unsigned int> *findAddress(DnsMessage &dns_msg, const char *name) {
	set<unsigned int> *ips = new set<unsigned int>();

	deque<DnsRR *> *answers = dns_msg.getAnswers(name);

	for (int i = 0; i < answers->size(); i++)
		switch (answers->at(i)->type_id) {
			case DNS_TYPE_A: {
				unsigned int ip = ((DnsRR_A *)answers->at(i)->data)->addr;
				ips->insert(ip);
				break;
			}

			case DNS_TYPE_CNAME: {
				const char *primary_name = ((DnsRR_CNAME *)answers->at(i)->data)->primary_name;
				set<unsigned int> *ips_ = findAddress(dns_msg, primary_name);
				ips->insert(ips_->begin(), ips_->end());
				delete ips_;
				break;
			}
		}

	delete answers;

	return ips;
}

void updateIp2NameTable(const Packet *packet) {
	char cmd[200];

	DnsMessage dns_msg;
	if (!dns_msg.fill(packet->payload))
		return;

	for (int i = 0; i < dns_msg.num_of_questions; i++) {
		if (dns_msg.questions[i].type_id != DNS_TYPE_A)
			continue;

		const char *name = dns_msg.questions[i].name;

		set<unsigned int> *ips = findAddress(dns_msg, name);
		for (set<unsigned int>::iterator it = ips->begin(); it != ips->end(); it++) {
			sprintf(cmd, "INSERT INTO ip_name VALUES('%s', '%s')", ip2str(*it).c_str(), name);
			sqlite_db->executeUpdate(cmd);
		}

		delete ips;
	}
}

Cluster::Cluster(ClusterType type) {
	this->type = type;
	this->src_ips = new set<unsigned int>();
}

Cluster::~Cluster() {
	delete this->src_ips;
}

NetflowCluster::NetflowCluster() : Cluster(CLUSTER_NETFLOW) {
	this->netflow_list = new deque<Netflow *>();
}

NetflowCluster::~NetflowCluster() {
	delete this->netflow_list;
}

Netflow *NetflowCluster::get(int id) {
	return this->netflow_list->at(id);
}

void NetflowCluster::add(Netflow *netflow) {
	this->netflow_list->push_back(netflow);
	this->src_ips->insert(netflow->conn->src_ip);
}

int NetflowCluster::size() {
	return this->netflow_list->size();
}

deque<double *> *NetflowCluster::netflowFeatures(map<Netflow *, double *> &netflow_feature_table, int num_of_features) {
	deque<double *> *feature_list = new deque<double *>();

	for (int i = 0; i < this->netflow_list->size(); i++) {
		double *feature = new double[num_of_features];
		memcpy(feature, netflow_feature_table[this->netflow_list->at(i)], num_of_features * sizeof(double));
		feature_list->push_back(feature);
	}

	return feature_list;
}

ScanCluster::ScanCluster() : Cluster(CLUSTER_SCAN) {
	this->scan_list = new deque<Scan *>();
}

ScanCluster::~ScanCluster() {
	delete this->scan_list;
}

Scan *ScanCluster::get(int id) {
	return this->scan_list->at(id);
}

void ScanCluster::add(Scan *scan) {
	this->scan_list->push_back(scan);
	this->src_ips->insert(scan->src_ip);
}

int ScanCluster::size() {
	return this->scan_list->size();
}

TimeWindow::TimeWindow() {
	this->cluster_list = new deque<Cluster *>();
	this->netflow_cluster_list = new deque<NetflowCluster *>();
	this->scan_cluster_list = new deque<ScanCluster *>();
}

TimeWindow::~TimeWindow() {
	for (int i = 0; i < this->cluster_list->size(); i++)
		delete this->cluster_list->at(i);
	delete this->cluster_list;

	delete this->netflow_cluster_list;

	delete this->scan_cluster_list;
}

void TimeWindow::add(NetflowCluster *netflow_cluster) {
	this->cluster_list->push_back(netflow_cluster);
	this->netflow_cluster_list->push_back(netflow_cluster);
}

void TimeWindow::add(ScanCluster *scan_cluster) {
	this->cluster_list->push_back(scan_cluster);
	this->scan_cluster_list->push_back(scan_cluster);
}

Cluster *TimeWindow::getC(int id) {
	return this->cluster_list->at(id);
}

NetflowCluster *TimeWindow::getNC(int id) {
	return this->netflow_cluster_list->at(id);
}

ScanCluster *TimeWindow::getSC(int id) {
	return this->scan_cluster_list->at(id);
}

int TimeWindow::size() {
	return this->cluster_list->size();
}

int TimeWindow::ncSize() {
	return this->netflow_cluster_list->size();
}

int TimeWindow::scSize() {
	return this->scan_cluster_list->size();
}

Host::Host(unsigned int ip, unsigned int last_correlated_tw_id) {
	this->ip = ip;
	this->last_correlated_tw_id = last_correlated_tw_id;
	this->score = 0;
}

void printTimeWindow(int tw_id) {
	deque<set<unsigned int> *> *cluster_list = timewindow_list[tw_id];
	fprintf(stdout, "Time Window %d has %d clusters\n", tw_id, (int)cluster_list->size());
	for (int j = 0; j < cluster_list->size(); j++) {
		set<unsigned int> *cluster = cluster_list->at(j);
		fprintf(stdout, "\tCluster %d has %d hosts\n", j, (int)cluster->size());
	}
	fflush(stdout);
}

void printHostScores() {
	fprintf(stdout, "\n --------------- Host Scores ---------------- \n");
	for (HostTable::iterator it = host_table.begin(); it != host_table.end(); it++)
		fprintf(stdout, "%s\t= %f\n", ip2str(it->first).c_str(), it->second->score);
	fflush(stdout);
}

void print(const char *data) {
//	fprintf(output_file, "%s\n", data);
//	fflush(output_file);

	fprintf(stdout, "%s\n", data);
	fflush(stdout);

//	fprintf(stderr, "%s\n", data);
}

