#ifndef UTILITY_NETFLOW_H
#define UTILITY_NETFLOW_H

#include <map>
#include <set>
#include <deque>
#include <string>
#include "packet.h"

using namespace std;

namespace utility {
	#define TCP_START(tcp) (((tcp)->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN && ((tcp)->flags & TCP_FLAG_ACK) == 0)
	#define TIMEOUT_CHECK 60
	#define TCP_TIMEOUT 600
	#define UDP_TIMEOUT 60

	class Packet;

	class Connection {
		public:
			unsigned char proto;
			unsigned int src_ip;
			unsigned short src_port;
			unsigned int dst_ip;
			unsigned short dst_port;

			Connection();
			Connection(Connection *conn);

			Connection *reverse();
	};

	class Netflow {
		public:
			double start_time;
			double end_time;

			Connection *conn;

			unsigned int src_pkts;
			unsigned int src_bytes;
			deque<Packet *> *src_pkts_list;

			unsigned int dst_pkts;
			unsigned int dst_bytes;
			deque<Packet *> *dst_pkts_list;

			bool is_completed;

			Netflow();
			Netflow(Packet *, Connection *);
			~Netflow();

			string toString(double = 0, double = -1, double = -1);
			double getDuration(double, double) const;
			char *toBinary(int &) const;
			static deque<Packet *> *getPktsList(const deque<Packet *> *, double, double);
			static unsigned int getPkts(const deque<Packet *> *, double, double);
			static unsigned int getBytes(const deque<Packet *> *, double, double);
			static char *getPayload(const deque<Packet *> *, double, double);
			static Netflow *fromString(const char *);
	};

	class ConnectionCompare {
		public:
			bool operator()(const Connection *, const Connection *) const;
	};

	class NetflowCompare {
		public:
			bool operator()(const Netflow *, const Netflow *) const;
	};

	typedef map<Connection *, Netflow *, ConnectionCompare> NetflowTable;
	typedef pair<Connection *, Netflow *> NetflowTablePair;

	struct NetflowBinary {
		double start_time;
		double end_time;
		unsigned char proto;
		unsigned int src_ip;
		unsigned short src_port;
		unsigned int src_pkts;
		unsigned int src_bytes;
		unsigned int dst_ip;
		unsigned short dst_port;
		unsigned int dst_pkts;
		unsigned int dst_bytes;
	} __attribute__((packed));

	class NetflowGenerator {
		public:
			NetflowTable *netflow_table;
			double last_packet_time;

			NetflowGenerator();
			~NetflowGenerator();

			Netflow *process(Packet *);
			Netflow *updateNetflowTable(Packet *, Connection *, char);
			deque<Netflow *> *getTimeoutNetflows();
			deque<Netflow *> *flush();
			void updateAsciiCount(unsigned int *, unsigned short *);
	};
}

#endif

