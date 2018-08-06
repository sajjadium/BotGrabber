#ifndef INET_ADDRESS_H
#define INET_ADDRESS_H

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <string>

using namespace std;

namespace utility {
	class InetAddress {
		public:
			string address;
			unsigned short port;

			InetAddress();
			InetAddress(const char *);
			InetAddress(unsigned short);
			InetAddress(const char *, unsigned short);
			InetAddress(const struct sockaddr_in *);
			~InetAddress();

			struct sockaddr_in *getSocketAddress();

			static InetAddress *getLocal(int);
			static InetAddress *getRemote(int);
			static unsigned int getHostByName(const char *);
	};
}

#endif

