#ifndef TCP_SERVER_SOCKET_H
#define TCP_SERVER_SOCKET_H

namespace utility {
	class InetAddress;
	class TcpSocket;

	class TcpServerSocket {
		public:
			int socketId;

			InetAddress *local;

			TcpServerSocket(InetAddress *);
			~TcpServerSocket();

			bool bind();
			bool listen();
			TcpSocket *accept();
			void close();
	};
}

#endif

