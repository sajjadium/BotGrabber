#include "netflow.h"

struct ConnectionCompare {
	bool operator()(const Connection *conn1, const Connection *conn2) const {
		return (memcmp(conn1, conn2, sizeof(Connection)) < 0);
	}
};

struct NetFlowCompare {
	bool operator()(const NetFlow *nf1, const NetFlow *nf2) const {
		return nf1->start_time < nf2->start_time;
	}
};

typedef map<Connection *, NetFlow *, ConnectionCompare> NetFlowTable;
typedef set<NetFlow *, NetFlowCompare> NetFlowSet;
typedef pair<Connection *, NetFlow *> NetFlowTableType;

NetFlowTable *netflow_table = NULL;
unsigned int timewindow_start = 0;
unsigned int timewindow_size;

void printMessage(const Message* message) {
	printf("%d %s %s:%d > %s:%d %d %s\n", message->time,
										IP_PROTO_STR(message->conn.proto),
										strIp(message->conn.src_ip).c_str(), message->conn.src_port,
										strIp(message->conn.dst_ip).c_str(), message->conn.dst_port,
										message->bytes,
										TCP_SYN_STR(message->is_syn));
}

void writeNetFlow(const NetFlow *netflow) {
	fwrite(netflow, sizeof(NetFlow), 1, stdout);
	fflush(stdout);
}

void outputNetFlow(const NetFlow *netflow) {
	writeNetFlow(netflow);
//	printNetFlow(netflow);
}

void outputNetFlowCount(const unsigned int count) {
	fwrite(&count, sizeof(unsigned int), 1, stdout);
	fflush(stdout);
//	printf("%d\n", count);
}

NetFlow *createNetFlow(const Message* message) {
	NetFlow* netflow = new NetFlow;
	memset(netflow, 0, sizeof(NetFlow));

	netflow->start_time = message->time;
	netflow->end_time = message->time;

	netflow->conn = message->conn;

	netflow->pkts_sent = 1;
	netflow->bytes_sent = message->bytes;

	return netflow;
}

void updateNetFlowTable(Message *message) {
	NetFlowTable::iterator netflow_table_it;
	NetFlow* netflow = NULL;

	switch (message->conn.proto) {
		case IP_PROTO_TCP:
			if (message->is_syn) {
				netflow_table_it = netflow_table->find(&(message->conn));
				if (netflow_table_it != netflow_table->end()) {
					delete netflow_table_it->second;
					netflow_table->erase(netflow_table_it);
				}
				netflow = createNetFlow(message);
				netflow_table->insert(NetFlowTableType (&(netflow->conn), netflow));
			} else {
				Connection conn = message->conn;
	
				netflow_table_it = netflow_table->find(&conn);
				if (netflow_table_it != netflow_table->end()) {
					netflow = netflow_table_it->second;
					netflow->end_time = message->time;
					netflow->pkts_sent ++;
					netflow->bytes_sent += message->bytes;
				} else {
					conn.src_ip = message->conn.dst_ip;
					conn.src_port = message->conn.dst_port;
					conn.dst_ip = message->conn.src_ip;
					conn.dst_port = message->conn.src_port;
	
					netflow_table_it = netflow_table->find(&conn);
					if (netflow_table_it != netflow_table->end()) {
						netflow = netflow_table_it->second;
						netflow->end_time = message->time;
						netflow->pkts_recv ++;
						netflow->bytes_recv += message->bytes;
					}
				}
			}

			break;
	}
}

void handleEndOfTimeWindow() {
	list<Connection *> *timeout_netflow = new list<Connection *>();
	NetFlowSet *output_netflow = new NetFlowSet();

	for (NetFlowTable::iterator it = netflow_table->begin(); it != netflow_table->end(); it++) {
		if (it->second->end_time > timewindow_start)
			output_netflow->insert(it->second);

		if (timewindow_start + timewindow_size - it->second->end_time >= TCP_TIMEOUT)
			timeout_netflow->push_back(it->first);
	}

	outputNetFlowCount(output_netflow->size());
	for (NetFlowSet::iterator it = output_netflow->begin(); it != output_netflow->end(); it++) {
		(*it)->start_time = ((*it)->start_time < timewindow_start) ? timewindow_start : (*it)->start_time;
		outputNetFlow(*it);

		(*it)->pkts_sent = 0;
		(*it)->bytes_sent = 0;
		(*it)->pkts_recv = 0;
		(*it)->bytes_recv = 0;
	}

	for (list<Connection *>::iterator it = timeout_netflow->begin(); it != timeout_netflow->end(); it++) {
		NetFlowTable::iterator netflow_table_it = netflow_table->find(*it);
		delete netflow_table_it->second;
		netflow_table->erase(netflow_table_it);
	}

	delete timeout_netflow;
	delete output_netflow;
}

void processMessage(unsigned char* arg, const struct pcap_pkthdr* pcap_header, const unsigned char* pcap_frame) {
	Message *message = new Message;
	memset(message, 0, sizeof(Message));

	Packet *packet = new Packet(pcap_header, pcap_frame);

	message->time = packet->time;

	if (timewindow_start == 0)
		timewindow_start = message->time;

	if (message->time - timewindow_start > timewindow_size) {
		handleEndOfTimeWindow();
		timewindow_start += timewindow_size;
	}

	bool is_ok = true;
	if (packet->ip4_hdr != NULL) {
		message->conn.src_ip = ntohl(packet->ip4_hdr->src_ip);
		message->conn.dst_ip = ntohl(packet->ip4_hdr->dst_ip);

		if (packet->tcp_hdr != NULL) {
			message->conn.proto = IP_PROTO_TCP;

			message->conn.src_port = ntohs(packet->tcp_hdr->src_port);
			message->conn.dst_port = ntohs(packet->tcp_hdr->dst_port);

			if (TCP_START(packet->tcp_hdr))
				message->is_syn = true;
			else
				message->is_syn = false;
		} else {
			is_ok = false;
		}
	} else {
		is_ok = false;
	}

	if (is_ok) {
		message->bytes = packet->payload_len;
		updateNetFlowTable(message);
	}

	delete message;
	delete packet;
}

int main (int argc, char **argv) {
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *pcap_id = pcapOpenOffline("-");

	if (pcap_id == NULL)
		return 1;

	timewindow_size = atoi(argv[1]);
	netflow_table = new NetFlowTable();

	pcap_loop(pcap_id, -1, processMessage, NULL);

	pcap_close(pcap_id);

	handleEndOfTimeWindow();

	for(NetFlowTable::iterator it = netflow_table->begin(); it != netflow_table->end(); it++)
		delete it->second;

	delete netflow_table;

	return 0;
}

