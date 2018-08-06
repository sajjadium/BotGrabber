#include "botgrabber.h"

set<unsigned int> bot_list;

extern HostTable host_table;

extern double CORRELATION_THRESHOLD;
extern double BOT_THRESHOLD;
extern double MAX_TW_SCORE;
extern unsigned int MAX_NUM_TIMEWINDOW;
extern unsigned int TIMEWINDOW_ID;
extern deque<TimeWindow *> timewindow_list;
extern SqliteDB *sqlite_db;

set<unsigned int> *unionSet(set<unsigned int> *set1, set<unsigned int> *set2) {
	set<unsigned int> *union_set = new set<unsigned int>();

	for (set<unsigned int>::iterator it = set1->begin(); it != set1->end(); it++)
		union_set->insert(*it);

	for (set<unsigned int>::iterator it = set2->begin(); it != set2->end(); it++)
		union_set->insert(*it);

	return union_set;
}

set<unsigned int> *intersectSet(set<unsigned int> *set1, set<unsigned int> *set2) {
	set<unsigned int> *intersect_set = new set<unsigned int>();
	set<unsigned int> *set_1 = NULL, *set_2 = NULL;

	if (set1->size() <= set2->size()) {
		set_1 = set1;
		set_2 = set2;
	} else {
		set_1 = set2;
		set_2 = set1;
	}

	for (set<unsigned int>::iterator it = set_1->begin(); it != set_1->end(); it++)
		if (set_2->count(*it) == 1)
			intersect_set->insert(*it);
	
	return intersect_set;
}

double correlate(Cluster *c1, Cluster *c2, unsigned int ip, int distance) {
	deque<unsigned int>::iterator it_u, it_i;
	deque<unsigned int> union_set(c1->src_ips->size() + c2->src_ips->size());
	deque<unsigned int> intersect_set(c1->src_ips->size() + c2->src_ips->size());

	it_u = set_union(c1->src_ips->begin(), c1->src_ips->end(), c2->src_ips->begin(), c2->src_ips->end(), union_set.begin());
	it_i = set_intersection(c1->src_ips->begin(), c1->src_ips->end(), c2->src_ips->begin(), c2->src_ips->end(), intersect_set.begin());

	int union_size = it_u - union_set.begin();
	int interset_size = it_i - intersect_set.begin();

	double weight;
	if (c1->type == CLUSTER_NETFLOW && c2->type == CLUSTER_NETFLOW)
		weight = 1;
	else if (c1->type != CLUSTER_NETFLOW && c2->type != CLUSTER_NETFLOW)
		weight = 3;
	else
		weight = 2;

	double score = 1 - exp(-weight * (double)interset_size / union_size * interset_size * 1.0 / (1 + distance));

	return score;
}

void addNewIpsToHostTable(int tw_id) {
	for (int i = 0; i < timewindow_list[tw_id]->size(); i++) {
		Cluster *cluster = timewindow_list[tw_id]->getC(i);
		for (set<unsigned int>::iterator it = cluster->src_ips->begin(); it != cluster->src_ips->end(); it++) {
			if (bot_list.count(*it) == 0 && host_table.find(*it) == host_table.end())
				host_table[*it] = new Host(*it, tw_id);
		}
	}
}

void correlation() {
	addNewIpsToHostTable(TIMEWINDOW_ID);

	HostTable::iterator ht_it = host_table.begin();
	while (ht_it != host_table.end()) {
		Host *host = ht_it->second;

		double max_score = -1;
		int correlated_tw_id = -1;
		deque<pair<int, int> > final_correlated_cluster_ids;

		for (int tw_id = TIMEWINDOW_ID; tw_id >= max(0, (int)(TIMEWINDOW_ID - MAX_NUM_TIMEWINDOW)); tw_id--) {
			deque<pair<int, int> > correlated_cluster_ids;

			set<int> c_set, _set;

			for (int cc_id = 0; cc_id < timewindow_list[TIMEWINDOW_ID]->size(); cc_id++) {
				Cluster *c_cluster = timewindow_list[TIMEWINDOW_ID]->getC(cc_id);

				if (c_cluster->src_ips->count(host->ip) == 0)
					continue;

				for (int c_id = 0; c_id < timewindow_list[tw_id]->size(); c_id++) {
					Cluster *cluster = timewindow_list[tw_id]->getC(c_id);

					if ((TIMEWINDOW_ID == tw_id && cc_id >= c_id) || cluster->src_ips->count(host->ip) == 0)
						continue;

					if (correlate(c_cluster, cluster, host->ip, TIMEWINDOW_ID - tw_id) >= CORRELATION_THRESHOLD) {
						c_set.insert(cc_id);
						_set.insert(c_id);

						correlated_cluster_ids.push_back(pair<int, int>(cc_id, c_id));
					}
				}
			}

			if (max_score == -1 || (c_set.size() + _set.size()) > max_score) {
				max_score = c_set.size() + _set.size();
				correlated_tw_id = tw_id;
				final_correlated_cluster_ids.clear();
				final_correlated_cluster_ids.insert(final_correlated_cluster_ids.end(), correlated_cluster_ids.begin(), correlated_cluster_ids.end());
			}
		}

		char temp[200];
		if (max_score > 0) {
			host->score += min(max_score, MAX_TW_SCORE);
			host->last_correlated_tw_id = TIMEWINDOW_ID;

//			if (host->score >= BOT_THRESHOLD) {
//				bot_list.insert(host->ip);
//				sprintf(temp, "\t%s", ip2str(host->ip).c_str());
//				print(temp);
//				host_table.erase(ht_it++);
//			} else
				ht_it++;
		} else {
			host->score = max(0.0, host->score - (TIMEWINDOW_ID - host->last_correlated_tw_id));
			ht_it++;
		}

		sprintf(temp, "INSERT INTO scores VALUES ('%s', %u, %f)", ip2str(host->ip).c_str(), TIMEWINDOW_ID, host->score);
		sqlite_db->executeUpdate(temp);

		for (int i = 0; i < final_correlated_cluster_ids.size(); i++) {
			sprintf(temp, "INSERT INTO correlations VALUES ('%s', %u, %u, %u, %u)", ip2str(host->ip).c_str(), TIMEWINDOW_ID, correlated_tw_id, final_correlated_cluster_ids[i].first, final_correlated_cluster_ids[i].second);
			sqlite_db->executeUpdate(temp);
		}

//		if (bot_list.count(host->ip) > 0)
//			delete host;
	}
}

