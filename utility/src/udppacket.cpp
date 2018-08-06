#include "udppacket.h"
#include "inetaddress.h"

namespace utility {
	UdpPacket::UdpPacket(InetAddress *remote, char *data, int size) {
		this->remote = remote;
		this->data = data;
		this->size = size;
	}

	UdpPacket::UdpPacket(char *data, int size) {
		this->remote = NULL;
		this->data = data;
		this->size = size;
	}

	UdpPacket::~UdpPacket() {
		if (this->remote != NULL)
			delete this->remote;
	}
}

