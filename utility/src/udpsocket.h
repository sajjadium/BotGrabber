#ifndef UDP_SOCKET_H
#define UDP_SOCKET_H

#include <string>

using namespace std;

namespace utility {
	class UdpPacket;
	class InetAddress;

	class UdpSocket {
		public:
			int socketId;
			InetAddress *local;

			UdpSocket();
			UdpSocket(InetAddress *);
			~UdpSocket();

			bool bind();
			int send(const UdpPacket *);
			int receive(UdpPacket *);
			void close();
	};
}

#endif

