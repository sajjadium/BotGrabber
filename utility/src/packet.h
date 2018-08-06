#ifndef UTILITY_PACKET_H
#define UTILITY_PACKET_H

#include <string>
#include <deque>
#include <map>
#include <pcap.h>

using namespace std;

namespace utility {
	#define ETHERNET_HEADER_LEN 14
	#define IP_HEADER_LEN 20
	#define PSEUDO_HEADER_LEN 12
	#define ICMP_HEADER_LEN 4
	#define TCP_HEADER_LEN 20
	#define UDP_HEADER_LEN 8

	#define IP_OPT_LEN(ip) (((((ip)->vhl) & 0x0F) * 4) - IP_HEADER_LEN)
	#define TCP_OPT_LEN(tcp) (((((tcp)->len & 0xF0) >> 4) * 4) - TCP_HEADER_LEN)

	#define ETHERNET_TYPE_IP 0x0800

	#define IP_PROTO_ICMP 1
	#define IP_PROTO_TCP 6
	#define IP_PROTO_UDP 17
	#define IP_FLAG_MF 0x0020

	#define IP_V(vhl) ((vhl) >> 4)
	#define IP_IS_MF(ip) (((ip)->off & IP_FLAG_MF) == IP_FLAG_MF)

	#define TCP_FLAG_FIN 0x01
	#define TCP_FLAG_SYN 0x02
	#define TCP_FLAG_RST 0x04
	#define TCP_FLAG_PSH 0x08
	#define TCP_FLAG_ACK 0x10
	#define TCP_FLAG_URG 0x20

	#define TCP_IS_FIN(flags) ((flags & TCP_FLAG_FIN) == TCP_FLAG_FIN)
	#define TCP_IS_SYN(flags) ((flags & TCP_FLAG_SYN) == TCP_FLAG_SYN)
	#define TCP_IS_RST(flags) ((flags & TCP_FLAG_RST) == TCP_FLAG_RST)
	#define TCP_IS_PSH(flags) ((flags & TCP_FLAG_PSH) == TCP_FLAG_PSH)
	#define TCP_IS_ACK(flags) ((flags & TCP_FLAG_ACK) == TCP_FLAG_ACK)
	#define TCP_IS_URG(flags) ((flags & TCP_FLAG_URG) == TCP_FLAG_URG)

	struct Mac {
		unsigned char byte0;
		unsigned char byte1;
		unsigned char byte2;
		unsigned char byte3;
		unsigned char byte4;
		unsigned char byte5;
	} __attribute__((packed));

	struct EthernetHeader {
		Mac dst_mac;			/* Destination host address */
		Mac src_mac;			/* Source host address */
		unsigned short type;	/* IP? ARP? RARP? etc */
	} __attribute__((packed));

	struct Ip4Header {
		unsigned char vhl;		/* version << 4 | header length >> 2 */
		unsigned char tos;		/* type of service */
		unsigned short len;		/* total length */
		unsigned short id;		/* identification */
		unsigned short off;		/* fragment offset field */
		unsigned char ttl;		/* time to live */
		unsigned char proto;	/* protocol */
		unsigned short sum;		/* checksum */
		unsigned int src_ip;	/* source address */
		unsigned int dst_ip;	/* dest address */
		char *opt;				/* options */
	} __attribute__((packed));

	struct TcpHeader {
		unsigned short src_port;	/* source port */
		unsigned short dst_port;	/* destination port */
		unsigned int seq;			/* sequence number */
		unsigned int ack;			/* acknowledgement number */
		unsigned char len;			/* data offset, rsvd */
		unsigned char flags;		/* tcp flags */
		unsigned short win;			/* window */
		unsigned short sum;			/* checksum */
		unsigned short urp;			/* urgent pointer */
		char *opt;					/* options */
	} __attribute__((packed));

	struct UdpHeader {
		unsigned short src_port;	/* source port */
		unsigned short dst_port;	/* destination port */
		unsigned short len;			/* data len */
		unsigned short sum;			/* checksum */
	} __attribute__((packed));

	struct IcmpHeader {
		unsigned char type;
		unsigned char code;
		unsigned short sum;
	} __attribute__((packed));

	struct PseudoHeader {
		unsigned int src_ip;
		unsigned int dst_ip;
		unsigned char zero;
		unsigned char proto;
		unsigned short len;
	} __attribute__((packed));

	#define PACKET_STAT_SIZE (sizeof(double) + sizeof(unsigned short) + 256 * sizeof(unsigned short))

	class Packet {
		public:
			struct pcap_pkthdr *header;
			char *frame;
			unsigned short *ascii_count;

			// Datalink layer
			EthernetHeader *ethernet_hdr;

			// Network layer
			Ip4Header *ip4_hdr;

			// Transport layer
			IcmpHeader *icmp_hdr;
			TcpHeader *tcp_hdr;
			UdpHeader *udp_hdr;

			// Application layer
			unsigned short payload_len;
			unsigned short payload_caplen;
			char *payload;

			Packet();
			Packet(const struct pcap_pkthdr *, const char *);
			~Packet();

			bool decode();
			void fix();
			void setTime(double);
			double getTime();
	};
}

#endif

