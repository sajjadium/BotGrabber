#include <stdio.h>
#include <deque>
#include <time.h>
#include <utility/common.h>

using namespace utility;
using namespace std;

struct Scan {
	double time_stamp;
	int type;
	unsigned int src_ip;
	unsigned int dst_ip;
} __attribute__((packed));

int main(int argc, char *argv[]) {
	char scan_alert[300];

	while (fgets(scan_alert, sizeof(scan_alert), stdin) != NULL) {
		Scan scan;

		deque<string> *tokens = getTokens(scan_alert, " ");

		string time_str = tokens->at(0);
		struct tm time_utc;

		time_utc.tm_mon = str2int(time_str.substr(0, 2).c_str()) - 1;
		time_utc.tm_mday = str2int(time_str.substr(3, 2).c_str());
		time_utc.tm_year = str2int(time_str.substr(6, 2).c_str()) + 2000 - 1900;
		time_utc.tm_hour = str2int(time_str.substr(9, 2).c_str());
		time_utc.tm_min = str2int(time_str.substr(12, 2).c_str());
		time_utc.tm_sec = str2int(time_str.substr(15, 2).c_str());

		scan.time_stamp = timegm(&time_utc) + str2double(time_str.substr(17).c_str());

		deque<string> *type_tokens = getTokens(tokens->at(2).c_str(), "[:]");
		scan.type = str2int(type_tokens->at(1).c_str());

		scan.src_ip = str2ip(tokens->at(tokens->size() - 3).c_str());
		scan.dst_ip = str2ip(tokens->at(tokens->size() - 1).c_str());

		fprintf(stderr, "%f\t%d\t%s -> %s\n", scan.time_stamp, scan.type, ip2str(scan.src_ip).c_str(), ip2str(scan.dst_ip).c_str());

		fwrite(&scan, sizeof(Scan), 1, stdout);
		fflush(stdout);

		delete tokens;
		delete type_tokens;
	}

	return 0;
}

