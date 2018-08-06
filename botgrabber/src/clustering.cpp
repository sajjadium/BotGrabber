#include "botgrabber.h"

extern SqliteDB sqlite_db;
extern unsigned int TIMEWINDOW_ID;
extern double TIMEWINDOW_START;
extern double TIMEWINDOW_END;

extern map<Netflow *, Instance *> netflow_level_one_feature_table;
extern map<Netflow *, Instance *> netflow_level_two_feature_table;

Instance *getLevelOneFeatures(const Netflow *netflow) {
	Instance *ins = new Instance();

	unsigned int pkts_sent = Netflow::getPkts(netflow->pkts_stats_sent, TIMEWINDOW_START, TIMEWINDOW_END);
	unsigned int bytes_sent = Netflow::getBytes(netflow->pkts_stats_sent, TIMEWINDOW_START, TIMEWINDOW_END);
	unsigned int pkts_recv = Netflow::getPkts(netflow->pkts_stats_recv, TIMEWINDOW_START, TIMEWINDOW_END);
	unsigned int bytes_recv = Netflow::getBytes(netflow->pkts_stats_recv, TIMEWINDOW_START, TIMEWINDOW_END);

	// pkts sent
	ins->features->push_back(new DoubleFeature(pkts_sent));
	// bytes sent
	ins->features->push_back(new DoubleFeature(bytes_sent));
	// bpp sent
	if (pkts_sent > 0)
		ins->features->push_back(new DoubleFeature((double)bytes_sent / pkts_sent));
	else
		ins->features->push_back(new DoubleFeature(0));
	// pkts recv
	ins->features->push_back(new DoubleFeature(pkts_recv));
	// bytes recv
	ins->features->push_back(new DoubleFeature(bytes_recv));
	// bpp recv
	if (pkts_recv > 0)
		ins->features->push_back(new DoubleFeature((double)bytes_recv / pkts_recv));
	else
		ins->features->push_back(new DoubleFeature(0));

	return ins;
}

void createLevelOneFeatures(const deque<Netflow *> *netflow_list) {
	for (int i = 0; i < netflow_list->size(); i++)
		netflow_level_one_feature_table[netflow_list->at(i)] = getLevelOneFeatures(netflow_list->at(i));
}

void createLevelTwoFeatures(const deque<Netflow *> *netflow_list) {
	for (int nfi = 0; nfi < netflow_list->size(); nfi++) {
		Instance *ins = new Instance();

		char *payload_sent = Netflow::getPayload(netflow_list->at(nfi)->pkts_stats_sent, TIMEWINDOW_START, TIMEWINDOW_END);
		int payload_len_sent = Netflow::getBytes(netflow_list->at(nfi)->pkts_stats_sent, TIMEWINDOW_START, TIMEWINDOW_END);
		ins->features->push_back(new StringFeature(payload_sent, payload_len_sent));

		delete[] payload_sent;

		char *payload_recv = Netflow::getPayload(netflow_list->at(nfi)->pkts_stats_recv, TIMEWINDOW_START, TIMEWINDOW_END);
		int payload_len_recv = Netflow::getBytes(netflow_list->at(nfi)->pkts_stats_recv, TIMEWINDOW_START, TIMEWINDOW_END);
		ins->features->push_back(new StringFeature(payload_recv, payload_len_recv));

		delete[] payload_recv;

		netflow_level_two_feature_table[netflow_list->at(nfi)] = ins;
	}
}

deque<NetflowCluster *> *clustering(const deque<Netflow *> *netflow_list, map<Netflow *, Instance *> &netflow_feature_table, DistanceFunction distance_function, double max_err) {
	deque<NetflowCluster *> *cluster_list = new deque<NetflowCluster *>();

	if (netflow_list->size() > 0) {
		deque<Instance *> netflow_feature_list;
		for (int i = 0; i < netflow_list->size(); i++)
			netflow_feature_list.push_back(netflow_feature_table[netflow_list->at(i)]);

//		normalize(netflow_feature_list, num_of_features);

		deque<deque<int> *> *netflow_cluster_list = Clusterer::hierarchical(&netflow_feature_list, distance_function, max_err);

//		deque<deque<int> *> *netflow_cluster_list = Clusterer::kMeans(netflow_feature_list, num_of_features, 1, 100);
//		deque<deque<int> *> *netflow_cluster_list = Clusterer::xMeans2(netflow_feature_list, num_of_features, 1, netflow_feature_list.size(), max_err);
//		deque<deque<int> *> *netflow_cluster_list = Clusterer::xMeans(netflow_feature_list, num_of_features, 1, netflow_feature_list.size());

		for (int i = 0; i < netflow_cluster_list->size(); i++) {
			deque<int> *netflow_cluster = netflow_cluster_list->at(i);

			NetflowCluster *new_cluster = new NetflowCluster();

			for (int j = 0; j < netflow_cluster->size(); j++) {
				int netflow_id = netflow_cluster->at(j);
				new_cluster->add(netflow_list->at(netflow_id));
			}

			if (new_cluster->src_ips->size() < 2)
				delete new_cluster;
			else
				cluster_list->push_back(new_cluster);
		}

		// free netflow cluster list
		for (int i = 0; i < netflow_cluster_list->size(); i++)
			delete netflow_cluster_list->at(i);
		delete netflow_cluster_list;
	}

	return cluster_list;
}

