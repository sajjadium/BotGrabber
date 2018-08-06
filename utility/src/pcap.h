#ifndef UTILITY_PCAP_H
#define UTILITY_PCAP_H

#include <pcap.h>
#include <deque>
#include <set>
#include <string>

using namespace std;

namespace utility {
	struct TimeVal {
		unsigned int tv_sec;
		unsigned int tv_usec;
	};

	struct PcapPktHdr {
		struct TimeVal ts;
		unsigned int caplen;
		unsigned int len;
	};

	class Packet;

	class Pcap {
		public:
			pcap_t *pcap_id;
			char *name;
			char *filter_exp;
			int count;

			Pcap(const char *, const char *, int);
			~Pcap();

			bool openOnline();
			bool openOffline();
			bool applyFilter();
			Packet *nextPacket();
			void close();
	};

	class PcapDump {
		public:
			FILE *dump_id;
			char *dump_filename;

			PcapDump(FILE *);
			PcapDump(const char *);
			~PcapDump();

			bool open();
			void close();
			void writeGlobalHeader();
			void dump(const Packet *);
			void dump(const struct pcap_pkthdr *, const char *);
	};

	typedef pair<int, Packet *> PcapPacket;

	class PcapPacketCompare {
		public:
			bool operator()(const PcapPacket &, const PcapPacket &) const;
	};

	class PcapStream {
		public:
			int count;
			char *data_path;
			char *filter_exp;
			deque<Pcap *> *pcap_list;
			deque<char *> *file_list;
			multiset<PcapPacket, PcapPacketCompare> *pcap_pkts;

			PcapStream(const char *, const char *, int);
			~PcapStream();

			bool open();
			Packet *nextPacket();
			void close();
	};
}

#endif

