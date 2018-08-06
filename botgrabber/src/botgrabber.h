#ifndef DETECT_BOTNET_H
#define DETECT_BOTNET_H

#include <utility/netflow.h>
#include <utility/common.h>
#include <utility/sqlitedb.h>
#include <utility/ai.h>
#include <utility/pcap.h>
#include <utility/dns.h>
#include <utility/regex.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cmath>

#include <set>
#include <list>
#include <deque>
#include <map>
#include <string>
#include <algorithm>

using namespace utility;
using namespace std;

#define LEVEL_ONE_NUM_OF_FEATURES 6

enum ClusterType {CLUSTER_NETFLOW = 0, CLUSTER_SCAN = 1};

struct Scan {
	double time_stamp;
	int type;
	unsigned int src_ip;
	unsigned int dst_ip;
} __attribute__((packed));

class Cluster {
	public:
		ClusterType type;
		set<unsigned int> *src_ips;

		Cluster(ClusterType);
		virtual ~Cluster();

		virtual int size() = 0;
};

class NetflowCluster : public Cluster {
	public:
		deque<Netflow *> *netflow_list;

		NetflowCluster();
		~NetflowCluster();

		void add(Netflow *);
		Netflow *get(int);
		deque<double *> *netflowFeatures(map<Netflow *, double *> &, int);

		int size();
};

class ScanCluster : public Cluster {
	public:
		deque<Scan *> *scan_list;

		ScanCluster();
		~ScanCluster();

		void add(Scan *);
		Scan *get(int);

		int size();
};

class TimeWindow {
	public:
		deque<Cluster *> *cluster_list;
		deque<NetflowCluster *> *netflow_cluster_list;
		deque<ScanCluster *> *scan_cluster_list;

		TimeWindow();
		~TimeWindow();

		void add(NetflowCluster *);
		void add(ScanCluster *);

		Cluster *getC(int);
		NetflowCluster *getNC(int);
		ScanCluster *getSC(int);

		int size();
		int ncSize();
		int scSize();
};

class Host {
	public:
		unsigned int ip;
		double score;
		unsigned int last_correlated_tw_id;

		Host(unsigned int, unsigned int);
};

typedef map<unsigned int, Host *> HostTable;
typedef pair<unsigned int, Host *> HostTablePair;

// clustering
void createLevelOneFeatures(const deque<Netflow *> *);
void createLevelTwoFeatures(const deque<Netflow *> *);
deque<NetflowCluster *> *clustering(const deque<Netflow *> *, map<Netflow *, Instance *> &, DistanceFunction, double);

// correlation
void correlation();

// botgraber
void printTimeWindow(int);
void printHostScores();
void print(const char *);
void updateIp2NameTable(const Packet *packet);
double NCD(const char *, unsigned int, const char *, unsigned int);
string NCDErrorMsg(int);

#endif

