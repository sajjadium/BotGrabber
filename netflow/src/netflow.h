#ifndef NETFLOW_H
#define NETFLOW_H

#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <list>
#include <stdlib.h>
#include <utility.h>
#include <map>
#include <set>
#include <time.h>

using namespace std;
using namespace utility;

#define TCP_START(tcp) (((tcp)->flags & TCP_FLAG_SYN) == TCP_FLAG_SYN && ((tcp)->flags & TCP_FLAG_ACK) == 0)
#define TCP_SYN_STR(syn) (syn == true ? "SYN" : "")

#define TCP_TIMEOUT 60

struct Message {
	unsigned int time;
	Connection conn;
	unsigned short bytes;
	bool is_syn;
};

#endif

