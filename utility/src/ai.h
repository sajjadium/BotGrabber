#ifndef UTILITY_AI_H
#define UTILITY_AI_H

#include <deque>
#include <map>
#include <stdio.h>

using namespace std;

namespace utility {
	class DistanceTableKey {
		public:
			int i;
			int j;

			DistanceTableKey();
			DistanceTableKey(int, int);
	};

	class DistanceTableKeyCompare {
		public:
			bool operator()(const DistanceTableKey &, const DistanceTableKey &) const;
	};

	typedef map<DistanceTableKey, double, DistanceTableKeyCompare> DistanceTable;

	class MergedCluster {
		public:
			int z;
			int i;
			int j;
			double distance;

			MergedCluster(int, int, int, double);
	};

	class Feature {
		public:
			virtual ~Feature();
			virtual double distance(const Feature *) = 0;
	};

	class DoubleFeature : public Feature {
		public:
			double data;

			DoubleFeature(double);
			double distance(const Feature *);
	};

	class StringFeature : public Feature {
		public:
			char *data;
			int len;

			StringFeature(const char *, int);
			~StringFeature();
			double distance(const Feature *);
	};

	class Instance {
		public:
			deque<Feature *> *features;

			Instance();
			~Instance();
	};

	class Distance {
		public:
			static double euclidean(const Instance *, const Instance *);
			static double manhattan(const Instance *, const Instance *);
//			static double dice(const Instance *, const Instance *);
//			static double ncd(const Instance *, const Instance *);
	};

	typedef double (*DistanceFunction)(const Instance *, const Instance *);

	class Clusterer {
		public:
			static void createWekaInputFile(const deque<double *> *, int);
			static deque<deque<int> *> *readWekaOutput(FILE *, int);
			static deque<double *> *centroids(const deque<double *> *, int, const deque<deque<int> *> *);
			static deque<double> *error(const deque<double *> *, int, const deque<deque<int> *> *, const deque<double *> *);
			static deque<deque<int> *> *kMeans(const deque<double *> *, int, int, int);
			static deque<deque<int> *> *xMeans2(const deque<double *> *, int, int, int, double);
			static deque<deque<int> *> *xMeans(const deque<double *> *, int, int, int);
			static deque<deque<int> *> *hierarchical(const deque<Instance *> *, DistanceFunction, double);
	};
}

#endif

