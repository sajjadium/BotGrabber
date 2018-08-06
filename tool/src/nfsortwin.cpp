#include <deque>
#include <algorithm>

#include <stdio.h>
#include <time.h>

using namespace std;

struct NF {
	double start_time;
	double end_time;
};

class NFCompare {
	public:
		bool operator()(const char *str1, const char *str2) const {
			NF *nf1 = (NF *)str1;
			NF *nf2 = (NF *)str2;

			if (nf1->start_time != nf2->start_time)
				return (nf1->start_time < nf2->start_time);
			else if (nf1->end_time != nf2->end_time)
				return (nf1->end_time < nf2->end_time);
			else
				return false;
		}
};

int main(int argc, char *argv[]) {
	FILE *netflow_file = fopen(argv[1], "r");
	fseek(netflow_file, 0, SEEK_END);
	int file_size = ftell(netflow_file);
	fseek(netflow_file, 0, SEEK_SET);

	time_t time_ = time(NULL);

	deque<char *> netflow_list (file_size / 45, (char *)0);
	for (int i = 0; i < netflow_list.size(); i++) {
		char *nfbin = new char[45];
		fread(nfbin, 1, 45, netflow_file);
		netflow_list[i] = nfbin;
	}
	fclose(netflow_file);

	fprintf(stderr, "Loading Completed in %ld seconds.\n", time(NULL) - time_);

	time_ = time(NULL);

	sort(netflow_list.begin(), netflow_list.end(), NFCompare());

	fprintf(stderr, "Sorting Completed in %ld seconds.\n", time(NULL) - time_);

	time_ = time(NULL);

	for (int i = 0; i < netflow_list.size(); i++) {
		fwrite(netflow_list[i], 1, 45, stdout);
		delete[] netflow_list[i];
	}

	fprintf(stderr, "Writing Completed in %ld seconds.\n", time(NULL) - time_);

	return 0;
}

