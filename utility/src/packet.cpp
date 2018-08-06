#include "packet.h"
#include "common.h"

#include <cstring>
#include <cmath>
#include <vector>

namespace utility {
	Packet::Packet() {
		memset(this, 0, sizeof(Packet));
	}

	Packet::Packet(const struct pcap_pkthdr *pcap_header, const char *pcap_frame) {
		memset(this, 0, sizeof(Packet));

		this->ascii_count = new unsigned short[256];

		this->header = new struct pcap_pkthdr;
		memcpy(this->header, pcap_header, sizeof(struct pcap_pkthdr));

		try {
			this->frame = new char[this->header->caplen];
			memcpy(this->frame, pcap_frame, this->header->caplen);
		} catch (std::bad_alloc &e) {
			throw string("Frame can't be allocated");
		}
	}

	Packet::~Packet() {
		if (this->header != NULL) {
			delete this->header;
			this->header = NULL;
		}

		if (this->frame != NULL) {
			delete[] this->frame;
			this->frame = NULL;
		}

		if (this->ascii_count != NULL) {
			delete[] this->ascii_count;
			this->ascii_count = NULL;
		}
	}

	bool Packet::decode() {
		this->ethernet_hdr = (EthernetHeader *)(this->frame);
		unsigned short header_len = ETHERNET_HEADER_LEN;
		char *net_hdr = this->frame + ETHERNET_HEADER_LEN;
		if (net2host(this->ethernet_hdr->type) == ETHERNET_TYPE_IP) {
			if (IP_V(net_hdr[0]) == 4) {
				this->ip4_hdr = (Ip4Header *)net_hdr;
				header_len += IP_HEADER_LEN + IP_OPT_LEN(this->ip4_hdr);
				char *trans_hdr = net_hdr + IP_HEADER_LEN + IP_OPT_LEN(this->ip4_hdr);

				switch (this->ip4_hdr->proto) {
					case IP_PROTO_ICMP:
						this->icmp_hdr = (IcmpHeader *)trans_hdr;
						header_len += ICMP_HEADER_LEN;
						this->payload = trans_hdr + ICMP_HEADER_LEN;
						break;

					case IP_PROTO_TCP:
						this->tcp_hdr = (TcpHeader *)trans_hdr;
						header_len += TCP_HEADER_LEN;
						this->payload = trans_hdr + TCP_HEADER_LEN + TCP_OPT_LEN(this->tcp_hdr);
						this->payload_len = net2host(this->ip4_hdr->len) - (this->payload - net_hdr);
						break;

					case IP_PROTO_UDP:
						this->udp_hdr = (UdpHeader *)trans_hdr;
						header_len += UDP_HEADER_LEN;
						this->payload = trans_hdr + UDP_HEADER_LEN;
						this->payload_len = net2host(this->udp_hdr->len) - UDP_HEADER_LEN;
						break;

					default:
						return false;
				}
			} else
				return false;
		} else
			return false;

		if (this->header->caplen < header_len)
			return false;

		int frame_payload_len = this->header->len - (this->payload - this->frame);

		int p_caplen = this->header->caplen - (this->payload - this->frame);
		if (p_caplen > 0)
			this->payload_caplen = p_caplen - (frame_payload_len - this->payload_len);

		memset(this->ascii_count, 0, 512);
		for (int i = 0; i < this->payload_caplen; i++) {
			this->ascii_count[(unsigned char)this->frame[i]]++;
		}

		return true;
	}

	void Packet::fix() {
		if (this->header->caplen == this->header->len)
			return;

		this->header->len = this->header->caplen;

		if (this->ip4_hdr != NULL) {
			this->ip4_hdr->len = host2net(this->header->caplen - ETHERNET_HEADER_LEN);
//			this->ip4_hdr->sum = 0;
//			this->ip4_hdr->sum = checksum((char *)this->ip4_hdr, IP_HEADER_LEN + IP_OPT_LEN(this->ip4_hdr));

			if (this->icmp_hdr != NULL) {
//				unsigned short len = ICMP_HEADER_LEN + this->payload_caplen;
//				this->icmp_hdr->sum = 0;
//				this->icmp_hdr->sum = checksum((char *)this->icmp_hdr, len);
			} else if (this->tcp_hdr != NULL) {
//				unsigned short len = TCP_HEADER_LEN + TCP_OPT_LEN(this->tcp_hdr) + this->payload_caplen;
				unsigned short len = this->header->caplen - (this->ip4_hdr->len + ETHERNET_HEADER_LEN);
				if (this->tcp_hdr->len > len)
					this->tcp_hdr->len = 0x50;

//				char *data = new char[PSEUDO_HEADER_LEN + len];

//				PseudoHeader *pseudo_hdr = (PseudoHeader *)data;
//				pseudo_hdr->src_ip = this->ip4_hdr->src_ip;
//				pseudo_hdr->dst_ip = this->ip4_hdr->dst_ip;
//				pseudo_hdr->zero = 0;
//				pseudo_hdr->proto = this->ip4_hdr->proto;
//				pseudo_hdr->len = host2net(len);
//				this->tcp_hdr->sum = 0;
//				memcpy(data + PSEUDO_HEADER_LEN, this->tcp_hdr, len);
//				this->tcp_hdr->sum = checksum((char *)data, PSEUDO_HEADER_LEN + len);

//				delete[] data;
			} else if (this->udp_hdr != NULL) {
				unsigned short len = UDP_HEADER_LEN + this->payload_caplen;

//				char *data = new char[PSEUDO_HEADER_LEN + len];

//				PseudoHeader *pseudo_hdr = (PseudoHeader *)data;
//				pseudo_hdr->src_ip = this->ip4_hdr->src_ip;
//				pseudo_hdr->dst_ip = this->ip4_hdr->dst_ip;
//				pseudo_hdr->zero = 0;
//				pseudo_hdr->proto = this->ip4_hdr->proto;
//				pseudo_hdr->len = host2net(len);
				this->udp_hdr->len = host2net(len);
//				this->udp_hdr->sum = 0;
//				memcpy(data + PSEUDO_HEADER_LEN, this->udp_hdr, len);
//				this->udp_hdr->sum = checksum((char  *)data, PSEUDO_HEADER_LEN + len);

//				delete[] data;
			}
		}
	}

	void Packet::setTime(double new_time) {
		this->header->ts.tv_sec = new_time;
		this->header->ts.tv_usec = (new_time - this->header->ts.tv_sec) * 1000000;
	}

	double Packet::getTime() {
		return this->header->ts.tv_sec + this->header->ts.tv_usec / 1000000.0;
	}
}

