#include "inetaddress.h"

namespace utility {
	InetAddress::InetAddress() {
		this->address = "";
		this->port = 0;
	}

	InetAddress::InetAddress(const char *address) {
		this->address = address;
		this->port = 0;
	}

	InetAddress::InetAddress(unsigned short port) {
		this->address = "";
		this->port = port;
	}

	InetAddress::InetAddress(const char *address, unsigned short port) {
		this->address = address;
		this->port = port;
	}

	InetAddress::InetAddress(const struct sockaddr_in *socketAddress) {
		this->address = inet_ntoa(socketAddress->sin_addr);
		this->port = ntohs(socketAddress->sin_port);
	}

	InetAddress::~InetAddress() {
	}

	struct sockaddr_in *InetAddress::getSocketAddress() {
		struct sockaddr_in *socketAddress = new struct sockaddr_in;

		memset(socketAddress, 0, sizeof(struct sockaddr_in));
		socketAddress->sin_family = AF_INET;
		socketAddress->sin_addr.s_addr = InetAddress::getHostByName(this->address.c_str());
		socketAddress->sin_port = htons(this->port);

		return socketAddress;
	}

	InetAddress *InetAddress::getLocal(int socketId) {
		struct sockaddr_in local;
		socklen_t len;
		if (getsockname(socketId, (struct sockaddr *)&local, &len) == -1)
			return NULL;

		return new InetAddress(inet_ntoa(local.sin_addr), ntohs(local.sin_port));
	}

	InetAddress *InetAddress::getRemote(int socketId) {
		struct sockaddr_in remote;
		socklen_t len;
		if (getpeername(socketId, (struct sockaddr *)&remote, &len) == -1)
			return NULL;

		return new InetAddress(inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
	}

	unsigned int InetAddress::getHostByName(const char *address) {
		struct hostent *hostent_ = gethostbyname(address);
		if (hostent_ == NULL)
			return 0;

		unsigned int netByteOrderIp = *(in_addr_t *)hostent_->h_addr_list[0];

		return netByteOrderIp;
	}
}

