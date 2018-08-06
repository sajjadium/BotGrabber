#ifndef UDP_PACKET_H
#define UDP_PACKET_H

#include <string>

using namespace std;

namespace utility {
	class InetAddress;

	class UdpPacket {
		public:
			InetAddress *remote;
			char *data;
			int size;

			UdpPacket(InetAddress *, char *, int);
			UdpPacket(char *, int);
			~UdpPacket();
	};
}

#endif

