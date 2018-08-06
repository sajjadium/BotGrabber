#include "tcpsocket.h"
#include "inetaddress.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <cstring>

namespace utility {
	TcpSocket::TcpSocket(InetAddress *remote) {
		this->socketId = socket(AF_INET, SOCK_STREAM, 0);
		this->local = new InetAddress();
		this->remote = remote;
	}

	TcpSocket::TcpSocket(InetAddress *remote, InetAddress *local) {
		this->socketId = socket(AF_INET, SOCK_STREAM, 0);
		this->remote = remote;
		this->local = local;
	}

	TcpSocket::TcpSocket(int socketId) {
		this->socketId = socketId;
		this->local = InetAddress::getLocal(this->socketId);
		this->remote = InetAddress::getRemote(this->socketId);
	}

	TcpSocket::~TcpSocket() {
		delete this->local;
		delete this->remote;

		this->close();
	}

	bool TcpSocket::connect() {
		if (this->socketId == -1)
			return false;

		if (!this->bind()) {
			this->close();
			return false;
		}

		struct sockaddr_in *socketAddress = this->remote->getSocketAddress();

		if (::connect(this->socketId, (struct sockaddr *)socketAddress, sizeof(struct sockaddr_in)) == -1) {
			this->close();
			delete socketAddress;
			return false;
		}

		delete socketAddress;

		delete this->local;
		this->local = InetAddress::getLocal(this->socketId);

		return true;
	}

	bool TcpSocket::bind() {
		struct sockaddr_in *socketAddress = this->local->getSocketAddress();

		if (::bind(this->socketId, (struct sockaddr *)socketAddress, sizeof(struct sockaddr_in)) == -1) {
			delete socketAddress;
			return false;
		}

		delete socketAddress;

		delete this->local;
		this->local = InetAddress::getLocal(this->socketId);

		return true;
	}

	int TcpSocket::read(char *data, int dataSize) {
		int size;

		if (this->socketId != -1 && (size = ::read(this->socketId, data, dataSize)) > 0)
			return size;

		return -1;
	}

	int TcpSocket::write(const char *data, int dataSize) {
		int size;

		if (this->socketId != -1 && (size = ::write(this->socketId, data, dataSize)) > 0)
			return size;

		return -1;
	}

	void TcpSocket::close() {
		::close(this->socketId);
		this->socketId = -1;
	}
}

