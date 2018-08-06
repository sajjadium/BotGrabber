#include "tcpserversocket.h"
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
	TcpServerSocket::TcpServerSocket(InetAddress *local) {
		this->socketId = socket(AF_INET, SOCK_STREAM, 0);
		this->local = local;
	}

	TcpServerSocket::~TcpServerSocket() {
		delete this->local;
		this->close();
	}

	bool TcpServerSocket::bind() {
		struct sockaddr_in *socketAddress = this->local->getSocketAddress();

		if (::bind(this->socketId, (struct sockaddr *)socketAddress, sizeof(struct sockaddr_in)) == -1) {
			delete socketAddress;
			return false;
		}

		delete socketAddress;

		return true;
	}

	bool TcpServerSocket::listen() {
		if (this->socketId == -1)
			return false;

		if (!this->bind()) {
			this->close();
			return false;
		}

		if (::listen(this->socketId, SOMAXCONN) == -1) {
			this->close();
			return false;
		}

		delete this->local;

		this->local = InetAddress::getLocal(this->socketId);

		return true;
	}

	TcpSocket *TcpServerSocket::accept() {
		int newSocketId = ::accept(this->socketId, NULL, NULL);
		if (newSocketId == -1)
			return NULL;

		return new TcpSocket(newSocketId);
	}

	void TcpServerSocket::close() {
		::close(this->socketId);
		this->socketId = -1;
	}
}

