#include "netflow.h"
#include "common.h"

#include <algorithm>

#include <cstring>

using namespace std;

namespace utility {
	/******************** Connection ***********************/
	bool ConnectionCompare::operator()(const Connection *conn1, const Connection *conn2) const {
		if (conn1->proto != conn2->proto)
			return (conn1->proto < conn2->proto);
		else if (conn1->src_ip != conn2->src_ip)
			return (conn1->src_ip < conn2->src_ip);
		else if (conn1->src_port != conn2->src_port)
			return (conn1->src_port < conn2->src_port);
		else if (conn1->dst_ip != conn2->dst_ip)
			return (conn1->dst_ip < conn2->dst_ip);
		else if (conn1->dst_port != conn2->dst_port)
			return (conn1->dst_port < conn2->dst_port);
		else
			return false;
	}

	Connection::Connection() {
		memset(this, 0, sizeof(Connection));
	}

	Connection::Connection(Connection *conn) {
		memcpy(this, conn, sizeof(Connection));
	}

	Connection *Connection::reverse() {
		Connection *conn = new Connection();

		conn->proto = this->proto;

		conn->src_ip = this->dst_ip;
		conn->src_port = this->dst_port;

		conn->dst_ip = this->src_ip;
		conn->dst_port = this->src_port;

		return conn;
	}

	/******************* Netflow ********************/
	bool NetflowCompare::operator()(const Netflow *netflow1, const Netflow *netflow2) const {
		if (netflow1->start_time != netflow2->start_time)
			return (netflow1->start_time < netflow2->start_time);
		else if (netflow1->end_time != netflow2->end_time)
			return (netflow1->end_time < netflow2->end_time);
		else
			return ConnectionCompare()(netflow1->conn, netflow2->conn);
	}

	Netflow::Netflow() {
		memset(this, 0, sizeof(Netflow));

		this->conn = new Connection();

		this->src_pkts_list = new deque<Packet *>();

		this->dst_pkts_list = new deque<Packet *>();
	}

	Netflow::Netflow(Packet *packet, Connection *conn) {
		memset(this, 0, sizeof(Netflow));

		this->start_time = packet->getTime();
		this->end_time = packet->getTime();

		this->conn = new Connection(conn);

		this->src_pkts_list = new deque<Packet *>();

		this->dst_pkts_list = new deque<Packet *>();

		this->src_bytes = packet->payload_len;
		if (packet->payload_len > 0) {
			this->src_pkts_list->push_back(packet);
			this->src_pkts = 1;
		}
	}

	Netflow::~Netflow() {
		delete this->conn;

		for (int i = 0; i < this->src_pkts_list->size(); i++)
			delete this->src_pkts_list->at(i);
		delete this->src_pkts_list;

		for (int i = 0; i < this->dst_pkts_list->size(); i++)
			delete this->dst_pkts_list->at(i);
		delete this->dst_pkts_list;
	}

	deque<Packet *> *Netflow::getPktsList(const deque<Packet *> *pkts_list, double from_time, double to_time) {
		deque<Packet *> *pkts_list_ = new deque<Packet *>();

		for (int i = 0; i < pkts_list->size(); i++) {
			Packet *pkt = pkts_list->at(i);

			if (pkt->getTime() < from_time)
				continue;

			if (pkt->getTime() >= to_time)
				break;

			pkts_list_->push_back(pkt);
		}

		return pkts_list_;
	}

	unsigned int Netflow::getPkts(const deque<Packet *> *pkts_list, double from_time, double to_time) {
		unsigned int pkts_ = 0;

		deque<Packet *> *pkts_list_ = Netflow::getPktsList(pkts_list, from_time, to_time);

		pkts_ = pkts_list_->size();

		delete pkts_list_;

		return pkts_;
	}

	unsigned int Netflow::getBytes(const deque<Packet *> *pkts_list, double from_time, double to_time) {
		unsigned int bytes_ = 0;

		deque<Packet *> *pkts_list_ = Netflow::getPktsList(pkts_list, from_time, to_time);

		for (int i = 0; i < pkts_list_->size(); i++) {
			Packet *pkt = pkts_list_->at(i);

			bytes_ += pkt->payload_len;
		}

		delete pkts_list_;

		return bytes_;
	}

	char *Netflow::getPayload(const deque<Packet *> *pkts_list, double from_time, double to_time) {
		unsigned int bytes_ = Netflow::getBytes(pkts_list, from_time, to_time);
		char *payload_ = new char[bytes_];

		deque<Packet *> *pkts_list_ = Netflow::getPktsList(pkts_list, from_time, to_time);

		int byte_off = 0;
		for (int i = 0; i < pkts_list_->size(); i++) {
			Packet *pkt = pkts_list_->at(i);

			memcpy(payload_ + byte_off, pkt->payload, pkt->payload_len);
			byte_off += pkt->payload_len;
		}

		delete pkts_list_;

		return payload_;
	}

	Netflow *Netflow::fromString(const char *data) {
		deque<string> *tokens = getTokens(data, "\t|()->: ");

		Netflow *netflow = new Netflow();
		netflow->start_time = str2double(tokens->at(0).c_str());
		netflow->end_time = str2double(tokens->at(1).c_str());
		netflow->conn->proto = str2int(tokens->at(2).c_str());
		netflow->conn->src_ip = str2ip(tokens->at(3).c_str());
		netflow->conn->src_port = str2short(tokens->at(4).c_str());
		netflow->src_pkts = str2int(tokens->at(5).c_str());
		netflow->src_bytes = str2int(tokens->at(6).c_str());
		netflow->conn->dst_ip = str2ip(tokens->at(7).c_str());
		netflow->conn->dst_port = str2short(tokens->at(8).c_str());
		netflow->dst_pkts = str2int(tokens->at(9).c_str());
		netflow->dst_bytes = str2int(tokens->at(10).c_str());

		delete tokens;

		return netflow;
	}

	double Netflow::getDuration(double from_time = -1, double to_time = -1) const {
		from_time = (from_time == -1) ? this->start_time : from_time;
		to_time = (to_time == -1) ? this->end_time : to_time;

		return (this->is_completed ? this->end_time : to_time) - max(this->start_time, from_time);
	}

	string Netflow::toString(double base_time, double from_time, double to_time) {
		from_time = (from_time == -1) ? this->start_time : from_time;
		to_time = (to_time == -1) ? this->end_time : to_time;

		char temp[300];
/*		sprintf(temp, "%f\t%f\t%u\t%s\t%u\t%u\t%u\t%s\t%u\t%u\t%u",
				this->start_time,
				this->end_time,
				this->conn->proto,
				ip2str(this->conn->src_ip).c_str(), this->conn->src_port,
				this->src_pkts, this->src_bytes,
				ip2str(this->conn->dst_ip).c_str(),  this->conn->dst_port,
				this->dst_pkts, this->dst_bytes);
*/		sprintf(temp, "%1u %11.6f %11.6f %11.6f %2u %15s : %5u (%5u %9u) -> %15s : %5u (%5u %9u)",
				this->is_completed,
				this->start_time - base_time,
				this->end_time - base_time,
				this->getDuration(from_time, to_time),
				this->conn->proto,
				ip2str(this->conn->src_ip).c_str(), this->conn->src_port,
				this->getPkts(this->src_pkts_list, from_time, to_time), this->getBytes(this->src_pkts_list, from_time, to_time),
				ip2str(this->conn->dst_ip).c_str(),  this->conn->dst_port,
				this->getPkts(this->dst_pkts_list, from_time, to_time), this->getBytes(this->dst_pkts_list, from_time, to_time));

		return string(temp);
	}

	/******************* NetflowGenerator **********************/
	NetflowGenerator::NetflowGenerator() {
		this->netflow_table = new NetflowTable();
		this->last_packet_time = -1;
	}

	NetflowGenerator::~NetflowGenerator() {
		// free netflow_table
		NetflowTable::iterator it = this->netflow_table->begin();
		while (it != this->netflow_table->end()) {
			Netflow *netflow = it->second;
			netflow_table->erase(it++);
			delete netflow;
		}

		delete this->netflow_table;
	}

	Netflow *NetflowGenerator::updateNetflowTable(Packet *packet, Connection *conn, char flags) {
		NetflowTable::iterator nfit;
		Netflow *netflow = NULL;
		Netflow *complete_netflow = NULL;

		switch (conn->proto) {
			case IP_PROTO_TCP:
				if (TCP_IS_SYN(flags) && !TCP_IS_ACK(flags)) {
					nfit = this->netflow_table->find(conn);
					if (nfit != this->netflow_table->end()) {
						complete_netflow = nfit->second;
						complete_netflow->end_time = packet->getTime();
						complete_netflow->is_completed = true;
						this->netflow_table->erase(nfit);
					}
					netflow = new Netflow(packet, conn);
					this->netflow_table->insert(NetflowTablePair(netflow->conn, netflow));
				} else if (TCP_IS_FIN(flags) || TCP_IS_RST(flags)) {
					nfit = this->netflow_table->find(conn);
					if (nfit == this->netflow_table->end()) {	
						Connection *rconn = conn->reverse();
						nfit = this->netflow_table->find(rconn);
						delete rconn;
					}

					if (nfit != this->netflow_table->end()) {
						complete_netflow = nfit->second;
						complete_netflow->end_time = packet->getTime();
						complete_netflow->is_completed = true;
						this->netflow_table->erase(nfit);
					}
				} else {
					nfit = this->netflow_table->find(conn);
					if (nfit != this->netflow_table->end()) {
						netflow = nfit->second;

						netflow->end_time = packet->getTime();
						netflow->src_bytes += packet->payload_len;
						if (packet->payload_len > 0) {
							netflow->src_pkts++;
							netflow->src_pkts_list->push_back(packet);
						}
					} else {
						Connection *rconn = conn->reverse();

						nfit = this->netflow_table->find(rconn);
						if (nfit != this->netflow_table->end()) {
							netflow = nfit->second;
							netflow->end_time = packet->getTime();
							netflow->dst_bytes += packet->payload_len;
							if (packet->payload_len > 0) {
								netflow->dst_pkts++;
								netflow->dst_pkts_list->push_back(packet);
							}
						}

						delete rconn;
					}
				}

				break;

			case IP_PROTO_UDP:
				nfit = this->netflow_table->find(conn);
				if (nfit != this->netflow_table->end()) {
					netflow = nfit->second;
					netflow->end_time = packet->getTime();
					netflow->src_bytes += packet->payload_len;
					if (packet->payload_len > 0)
						netflow->src_pkts++;
				} else {
					Connection *rconn = conn->reverse();

					nfit = this->netflow_table->find(rconn);
					if (nfit != this->netflow_table->end()) {
						netflow = nfit->second;
						netflow->end_time = packet->getTime();
						netflow->dst_bytes += packet->payload_len;
						if (packet->payload_len > 0)
							netflow->dst_pkts++;
					} else {
						netflow = new Netflow(packet, conn);
						this->netflow_table->insert(NetflowTablePair(netflow->conn, netflow));
					}

					delete rconn;
				}

				break;
		}

		return complete_netflow;
	}

	deque<Netflow *> *NetflowGenerator::getTimeoutNetflows() {
		deque<Netflow *> *timeout_netflow_list = new deque<Netflow *>();

		NetflowTable::iterator it = this->netflow_table->begin();
		while (it != this->netflow_table->end()) {
			Netflow *netflow = it->second;
			if ((netflow->conn->proto == IP_PROTO_TCP && (this->last_packet_time - netflow->end_time) >= TCP_TIMEOUT) ||
				(netflow->conn->proto == IP_PROTO_UDP && (this->last_packet_time - netflow->end_time) >= UDP_TIMEOUT)) {
				this->netflow_table->erase(it++);
				netflow->is_completed = true;
				timeout_netflow_list->push_back(netflow);
			} else
				it++;
		}

		return timeout_netflow_list;
	}

	deque<Netflow *> *NetflowGenerator::flush() {
		deque<Netflow *> *flushed_netflow_list = new deque<Netflow *>();

		for (NetflowTable::iterator it = this->netflow_table->begin(); it != this->netflow_table->end(); it++)
			flushed_netflow_list->push_back(it->second);

		return flushed_netflow_list;
	}

	Netflow *NetflowGenerator::process(Packet *packet) {
		Netflow *netflow;
		Connection conn;
		char flags = 0;

		if (this->last_packet_time == -1)
			this->last_packet_time = packet->getTime();

		bool is_ok = true;
		if (packet->ip4_hdr != NULL) {
			conn.src_ip = net2host(packet->ip4_hdr->src_ip);
			conn.dst_ip = net2host(packet->ip4_hdr->dst_ip);

			if (packet->tcp_hdr != NULL) {
				conn.proto = IP_PROTO_TCP;

				conn.src_port = net2host(packet->tcp_hdr->src_port);
				conn.dst_port = net2host(packet->tcp_hdr->dst_port);

				flags = packet->tcp_hdr->flags;
			} else if (packet->udp_hdr != NULL) {
				conn.proto = IP_PROTO_UDP;

				conn.src_port = net2host(packet->udp_hdr->src_port);
				conn.dst_port = net2host(packet->udp_hdr->dst_port);
			} else {
				is_ok = false;
			}
		} else {
			is_ok = false;
		}

		if (is_ok)
			return this->updateNetflowTable(packet, &conn, flags);

		return NULL;
	}
}

