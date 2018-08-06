#include "udpsocket.h"
#include "udppacket.h"
#include "inetaddress.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <cstring>

namespace utility {
	UdpSocket::UdpSocket() {
		this->socketId = socket(AF_INET, SOCK_DGRAM, 0);
		this->local = new InetAddress();
	}

	UdpSocket::UdpSocket(InetAddress *local) {
		this->socketId = socket(AF_INET, SOCK_DGRAM, 0);
		this->local = local;
	}

	UdpSocket::~UdpSocket() {
		delete this->local;
		this->close();
	}

	bool UdpSocket::bind() {
		if (this->socketId == -1)
			return false;

		struct sockaddr_in *socketAddress = this->local->getSocketAddress();

		if (::bind(this->socketId, (struct sockaddr *)socketAddress, sizeof(struct sockaddr_in)) == -1) {
			delete socketAddress;
			this->close();
			return false;
		}

		delete socketAddress;

		return true;
	}

	int UdpSocket::send(const UdpPacket *udpPacket) {
		struct sockaddr_in *socketAddress = udpPacket->remote->getSocketAddress();

		int size = sendto(this->socketId, udpPacket->data, udpPacket->size, 0, (struct sockaddr *)socketAddress, sizeof(struct sockaddr_in));

		delete socketAddress;

		return size;
	}

	int UdpSocket::receive(UdpPacket *udpPacket) {
		struct sockaddr_in socketAddress;
		socklen_t len;

		int size = recvfrom(this->socketId, udpPacket->data, udpPacket->size, 0, (struct sockaddr *)&socketAddress, &len);
		if (size == -1)
			return -1;

		udpPacket->size = size;
		udpPacket->remote = new InetAddress(&socketAddress);

		return size;
	}

	void UdpSocket::close() {
		::close(this->socketId);
		this->socketId = -1;
	}
}

