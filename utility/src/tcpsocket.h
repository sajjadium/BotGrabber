#ifndef TCP_SOCKET_H
#define TCP_SOCKET_H

namespace utility {
	class InetAddress;

	class TcpSocket {
		public:
			InetAddress *local;
			InetAddress *remote;

			int socketId;

			TcpSocket(InetAddress *);
			TcpSocket(InetAddress *, InetAddress *);
			TcpSocket(int);
			~TcpSocket();

			bool bind();
			bool connect();
			int read(char *, int);
			int write(const char *, int);
			void close();
	};
}

#endif

