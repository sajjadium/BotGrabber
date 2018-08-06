#include "ai.h"
#include "common.h"

#include <algorithm>
#include <set>

#include <cmath>
#include <cstring>

using namespace std;

namespace utility {
	/*************** Feature & Instance ****************/
	Feature::~Feature() {
	}

	DoubleFeature::DoubleFeature(double data) {
		this->data = data;
	}

	double DoubleFeature::distance(const Feature *f) {
		return this->data - ((DoubleFeature *)f)->data;
	}

	StringFeature::StringFeature(const char *data, int len) {
		this->len = len;
		this->data = memclone(data, this->len);
	}

	StringFeature::~StringFeature() {
		delete[] this->data;
	}

	double StringFeature::distance(const Feature *f) {
		StringFeature *sf = (StringFeature *)f;

		return ncd(this->data, this->len, sf->data, sf->len);
	}

	Instance::Instance() {
		memset(this, 0, sizeof(Instance));

		this->features = new deque<Feature *>();
	}

	Instance::~Instance() {
		for (int i = 0; i < this->features->size(); i++)
			delete this->features->at(i);

		delete this->features;
	}

	/******************** Distance *********************/
	double Distance::euclidean(const Instance *ins1, const Instance *ins2) {
		double distance = 0;

		for (int i = 0; i < ins1->features->size(); i++) {
			Feature *f1 = ins1->features->at(i);
			Feature *f2 = ins2->features->at(i);

			distance += pow(f1->distance(f2), 2);
		}

		return pow(distance, 0.5);
	}

	double Distance::manhattan(const Instance *ins1, const Instance *ins2) {
		double distance = 0;

		for (int i = 0; i < ins1->features->size(); i++) {
			Feature *f1 = ins1->features->at(i);
			Feature *f2 = ins2->features->at(i);

			distance += abs(f1->distance(f2));
		}

		return distance;
	}
/*
	double Distance::dice(const Instance *ins1, const Instance *ins2) {
		int num_of_features = ins1->features->size();

		int total_len = 0;
		for (int i = 0; i < num_of_features; i++) {
			StringFeature *f1 = (StringFeature *)ins1->features->at(i);
			StringFeature *f2 = (StringFeature *)ins2->features->at(i);

			total_len += f1->len + f2->len;
		}

		deque<double> weights(num_of_features);
		for (int i = 0; i < num_of_features; i++) {
			StringFeature *f1 = (StringFeature *)ins1->features->at(i);
			StringFeature *f2 = (StringFeature *)ins2->features->at(i);

			weights[i] = (f1->len + f2->len) / (double)total_len;
		}

		double similarity = 0;
		for (int i = 0; i < ins1->features->size(); i++) {
			StringFeature *f1 = (StringFeature *)ins1->features->at(i);
			StringFeature *f2 = (StringFeature *)ins2->features->at(i);

			NgramTokenSet *nt_set1 = ngrams(f1->data, f1->len, 2);
			NgramTokenSet *nt_set2 = ngrams(f2->data, f2->len, 2);

			deque<NgramToken *> nt_set(min(nt_set1->size(), nt_set2->size()));
			deque<NgramToken *>::iterator it = set_intersection(nt_set1->begin(), nt_set1->end(), nt_set2->begin(), nt_set2->end(), nt_set.begin(), NgramTokenCompare());

			similarity += weights[i] * 2 * (it - nt_set.begin()) / (nt_set1->size() + nt_set2->size());

			NgramTokenSet::iterator it2 = nt_set1->begin();
			while (it2 != nt_set1->end()) {
				NgramToken *nt = *it2;
				nt_set1->erase(it2++);
				delete nt;
			}
			delete nt_set1;

			it2 = nt_set2->begin();
			while (it2 != nt_set2->end()) {
				NgramToken *nt = *it2;
				nt_set2->erase(it2++);
				delete nt;
			}
			delete nt_set2;
		}

		return 1 - similarity;
	}

	double Distance::ncd(const Instance *ins1, const Instance *ins2) {
		int num_of_features = ins1->features->size();

		int total_len = 0;
		for (int i = 0; i < num_of_features; i++) {
			StringFeature *f1 = (StringFeature *)ins1->features->at(i);
			StringFeature *f2 = (StringFeature *)ins2->features->at(i);

			total_len += f1->len + f2->len;
		}

		deque<double> weights(num_of_features);
		for (int i = 0; i < num_of_features; i++) {
			StringFeature *f1 = (StringFeature *)ins1->features->at(i);
			StringFeature *f2 = (StringFeature *)ins2->features->at(i);

			weights[i] = (f1->len + f2->len) / (double)total_len;
		}

		double distance = 0;

		for (int i = 0; i < ins1->features->size(); i++) {
			StringFeature *f1 = (StringFeature *)ins1->features->at(i);
			StringFeature *f2 = (StringFeature *)ins2->features->at(i);

			distance += weights[i] * ::ncd(f1->data, f1->len, f2->data, f2->len);
		}

		return distance;
	}
*/
	/******************* Clusterer ********************/
	DistanceTableKey::DistanceTableKey() {
		memset(this, 0, sizeof(DistanceTableKey));
	}

	DistanceTableKey::DistanceTableKey(int i, int j) {
		memset(this, 0, sizeof(DistanceTableKey));
		this->i = i;
		this->j = j;
	}

	MergedCluster::MergedCluster(int z, int i, int j, double distance) {
		this->z = z;
		this->i = i;
		this->j = j;
		this->distance = distance;
	}

	bool DistanceTableKeyCompare::operator()(const DistanceTableKey &dtk1, const DistanceTableKey &dtk2) const {
		return (memcmp(&dtk1, &dtk2, sizeof(DistanceTableKey)) < 0);
	}

	void Clusterer::createWekaInputFile(const deque<double *> *data, int num_of_features) {
		FILE *weka_file = fopen("weka.arff", "w");
		fprintf(weka_file, "@relation DetectBotnet\n");
		for (int i = 0; i < num_of_features; i++)
			fprintf(weka_file, "@attribute att%d real\n", i);

		fprintf(weka_file, "@data\n");
		for (int i = 0; i < data->size(); i++) {
			for (int j = 0; j < num_of_features; j++)
				fprintf(weka_file, "%f,", data->at(i)[j]);
			fprintf(weka_file, "\n");
		}
		fclose(weka_file);
	}

	deque<deque<int> *> *Clusterer::readWekaOutput(FILE *weka_out, int num_of_data) {
		deque<deque<int> *> *cluster_list = new deque<deque<int> *>();

		int nf_id, cluster_id;
		int *clusterid_list = new int[num_of_data];

		for (int i = 0; i < num_of_data; i++) {
			fscanf(weka_out, "%d %d", &nf_id, &cluster_id);
			clusterid_list[nf_id] = cluster_id;
		}

		// get number of clusters
		int num_of_clusters = -1;
		for (int i = 0; i < num_of_data; i++)
			if (num_of_clusters == -1 || clusterid_list[i] > num_of_clusters)
				num_of_clusters = clusterid_list[i];
		num_of_clusters ++;

		for (int i = 0; i < num_of_clusters; i++)
			cluster_list->push_back(new deque<int>);

		for (int i = 0; i < num_of_data; i++)
			cluster_list->at(clusterid_list[i])->push_back(i);

		delete[] clusterid_list;

		return cluster_list;
	}

	deque<double *> *Clusterer::centroids(const deque<double *> *data, int num_of_features, const deque<deque<int> *> *cluster_list) {
		deque<double *> *centers = new deque<double *>();

		for (int i = 0; i < cluster_list->size(); i++) {
			centers->push_back(new double[num_of_features]);
			memset(centers->at(i), 0, num_of_features * sizeof(double));

			for (int j = 0; j < cluster_list->at(i)->size(); j++)
				for (int k = 0; k < num_of_features; k++)
					centers->at(i)[k] += data->at(cluster_list->at(i)->at(j))[k];

			for (int k = 0; k < num_of_features; k++)
				centers->at(i)[k] /= cluster_list->at(i)->size();
		}

		return centers;
	}

	deque<double> *Clusterer::error(const deque<double *> *data, int num_of_features, const deque<deque<int> *> *cluster_list, const deque<double *> *centers) {
		deque<double> *errs = new deque<double>();

		for (int i = 0; i < cluster_list->size(); i++) {
			double err = 0;

//			for (int j = 0; j < cluster_list->at(i)->size(); j++)
//				err += Distance::euclidean(centers->at(i), data->at(cluster_list->at(i)->at(j)), num_of_features);

			errs->push_back(err);
		}

		return errs;
	}

	deque<deque<int> *> *Clusterer::xMeans(const deque<double *> *data, int num_of_features, int from_k, int to_k) {
		deque<deque<int> *> *cluster_list = NULL;
		FILE *weka_out;
		createWekaInputFile(data, num_of_features);

		char cmd[200];
		sprintf(cmd, "java -classpath weka.jar weka.clusterers.XMeans -I 100 -M 1000 -J 1000 -L %u -H %u -B 1.0 -C 0.5 -D 'weka.core.EuclideanDistance -R first-last' -S 10 -U 0 -p 0 -t weka.arff", from_k, to_k);

		if ((weka_out = popen(cmd, "r")) != NULL) {
			cluster_list = readWekaOutput(weka_out, data->size());

			pclose(weka_out);

			system("rm -f weka.arff");
		} else 
			fprintf(stderr, "Weka Error in XMeans\n");

		return cluster_list;
	}

	deque<deque<int> *> *Clusterer::xMeans2(const deque<double *> *data, int num_of_features, int from_k, int to_k, double max_err) {
		deque<deque<int> *> *cluster_list;

		for (int k = from_k; k <= to_k; k++) {
			cluster_list = kMeans(data, num_of_features, k, 500);
			if (cluster_list == NULL)
				break;

			deque<double *> *centers = centroids(data, num_of_features, cluster_list);
			deque<double> *errs = error(data, num_of_features, cluster_list, centers);

			// check errors
			bool is_finished = true;
			for (int i = 0; i < errs->size(); i++)
				if (errs->at(i) > max_err) {
					is_finished = false;
					break;
				}

			// free centers
			for (int i = 0; i < centers->size(); i++)
				delete[] centers->at(i);
			delete centers;

			// free errs
			delete errs;

			// check continue condition
			if (is_finished || k == to_k)
				break;
			else {
				// free cluster_list
				for (int i = 0; i < cluster_list->size(); i++)
					delete cluster_list->at(i);
				delete cluster_list;
			}
		}

		return cluster_list;
	}

	deque<deque<int> *> *Clusterer::kMeans(const deque<double *> *data, int num_of_features, int k, int num_of_iterations) {
		deque<deque<int> *> *cluster_list = NULL;
		FILE *weka_out;
		createWekaInputFile(data, num_of_features);

		char cmd[200];
		sprintf(cmd, "java -classpath weka.jar weka.clusterers.SimpleKMeans -N %u -I %u -A 'weka.core.EuclideanDistance -R first-last' -S 10 -p 0 -t weka.arff", k, num_of_iterations);

		if ((weka_out = popen(cmd, "r")) != NULL) {
			cluster_list = readWekaOutput(weka_out, data->size());

			pclose(weka_out);

			system("rm -f weka.arff");
		} else 
			fprintf(stderr, "Weka Error in KMeans\n");

		return cluster_list;
	}

	deque<deque<int> *> *Clusterer::hierarchical(const deque<Instance *> *data, DistanceFunction distance_function, double cutoff) {
		if (data->size() == 0)
			return NULL;

		int num_of_features = data->at(0)->features->size();

		DistanceTable distance_table;

		// calculate distances
		for (int di1 = 0; di1 < data->size(); di1++)
			for (int di2 = di1 + 1; di2 < data->size(); di2++)
				distance_table[DistanceTableKey(di1, di2)] = distance_function(data->at(di1), data->at(di2)); 

		// initialize clusters
		set<int> clusters;
		for (int i = 0; i < data->size(); i++)
			clusters.insert(i);

		int m = data->size();
		deque<MergedCluster *> Z;
		for (int s = 0; s < m - 1; s++) {
			// find min distance
			double min_distance = -1;
			DistanceTableKey dtk;
			for (DistanceTable::iterator it = distance_table.begin(); it != distance_table.end(); it++)
				if (min_distance == -1 || it->second < min_distance) {
					dtk = it->first;
					min_distance = it->second;
				}

			if (min_distance > cutoff) {
				break;
			}

			// merge clusters
			Z.push_back(new MergedCluster(m + s, dtk.i, dtk.j, min_distance));
			distance_table.erase(dtk);
			clusters.erase(dtk.i);
			clusters.erase(dtk.j);

			for (set<int>::iterator it = clusters.begin(); it != clusters.end(); it++) {
				int c = *it;
				DistanceTableKey c_i(min(c, dtk.i), max(c, dtk.i));
				DistanceTableKey c_j(min(c, dtk.j), max(c, dtk.j));
				distance_table[DistanceTableKey(c, m + s)] = (distance_table[c_i] + distance_table[c_j]) / 2.0;
				distance_table.erase(c_i);
				distance_table.erase(c_j);
			}

			clusters.insert(m + s);
		}

		map<int, deque<int> *> final_clusters;
		for (int ci = 0; ci < m; ci++) {
			final_clusters[ci] = new deque<int>();
			final_clusters[ci]->push_back(ci);
		}

		for (int zi = 0; zi < Z.size(); zi++) {
			final_clusters[Z[zi]->z] = new deque<int>();

			final_clusters[Z[zi]->z]->insert(final_clusters[Z[zi]->z]->begin(), final_clusters[Z[zi]->i]->begin(), final_clusters[Z[zi]->i]->end());
			final_clusters[Z[zi]->z]->insert(final_clusters[Z[zi]->z]->begin(), final_clusters[Z[zi]->j]->begin(), final_clusters[Z[zi]->j]->end());

			delete final_clusters[Z[zi]->i];
			delete final_clusters[Z[zi]->j];

			final_clusters.erase(Z[zi]->i);
			final_clusters.erase(Z[zi]->j);

			delete Z[zi];
		}

		deque<deque<int> *> *res_clusters = new deque<deque<int> *>();
		for (map<int, deque<int> *>::iterator it = final_clusters.begin(); it != final_clusters.end(); it++)
			res_clusters->push_back(it->second);

		return res_clusters;
	}
}

