#ifndef UTILITY_COMMON_H
#define UTILITY_COMMON_H

#include <string>
#include <deque>
#include <set>
#include <pcap.h>

using namespace std;

namespace utility {
	struct Mac;

	class StringCompare {
		public:
			bool operator()(const char *, const char *) const;
			bool operator()(const string &, const string &) const;
	};

	double pcapTime(const pcap_pkthdr *);

	Mac host2net(Mac);
	unsigned int host2net(unsigned int);
	unsigned short host2net(unsigned short);

	Mac net2host(Mac);
	unsigned int net2host(unsigned int);
	unsigned short net2host(unsigned short);

	string int2str(int);
	string long2str(long);
	string float2str(float);
	string double2str(double);
	string ip2str(unsigned int);
	string ip2str(const char *);
	string mac2str(Mac);

	short str2short(const char *);
	int str2int(const char *);
	long str2long(const char *);
	float str2float(const char *);
	double str2double(const char *);
	unsigned int str2ip(const char *);
	Mac str2mac(const char *);

	unsigned short readShort(const char *);
	unsigned int readInt(const char *);
	char *readline(FILE *);

	unsigned short checksum(const char *, unsigned short);

	char *strclone(const char *);
	string strltrim(const char *);
	string strrtrim(const char *);
	string strtrim(const char *);
	char *memclone(const char *, int);

	char *str2lower(char *);
	char *str2upper(char *);

	deque<char *> *listDirectory(const char *);

	deque<string> *getTokens(const char *, const char *);

	double mean(const deque<double> *);
	double stdev(const deque<double> *);

	double ncd(const char *, unsigned int, const char *, unsigned int);
	string ncdErrorMsg(int);
}

#endif

