SRCS=$(wildcard src/*.cpp)

SHARED_OBJS=$(patsubst src/%.cpp, obj/shared/%.o, $(SRCS))
STATIC_OBJS=$(patsubst src/%.cpp, obj/static/%.o, $(SRCS))

build: libutility.so libutility.a

libutility.so: $(SHARED_OBJS)
	g++ $(FLAGS) -shared -fPIC -o $@ $^ -lpcap -lpthread -lsqlite3

libutility.a: $(STATIC_OBJS)
	ar cr $@ $^

obj/shared/dns.o: src/dns.cpp src/dns.h src/common.h
	g++ -g -c -fPIC src/dns.cpp -o obj/shared/dns.o

obj/static/dns.o: src/dns.cpp src/dns.h src/common.h
	g++ -g -c src/dns.cpp -o obj/static/dns.o

obj/shared/dnsquestion.o: src/dnsquestion.cpp src/dns.h src/common.h
	g++ -g -c -fPIC src/dnsquestion.cpp -o obj/shared/dnsquestion.o

obj/static/dnsquestion.o: src/dnsquestion.cpp src/dns.h src/common.h
	g++ -g -c src/dnsquestion.cpp -o obj/static/dnsquestion.o

obj/shared/dnsrr.o: src/dnsrr.cpp src/dns.h src/common.h
	g++ -g -c -fPIC src/dnsrr.cpp -o obj/shared/dnsrr.o

obj/static/dnsrr.o: src/dnsrr.cpp src/dns.h src/common.h
	g++ -g -c src/dnsrr.cpp -o obj/static/dnsrr.o

obj/shared/dnsmessage.o: src/dnsmessage.cpp src/dns.h src/common.h
	g++ -g -c -fPIC src/dnsmessage.cpp -o obj/shared/dnsmessage.o

obj/static/dnsmessage.o: src/dnsmessage.cpp src/dns.h src/common.h
	g++ -g -c src/dnsmessage.cpp -o obj/static/dnsmessage.o

obj/shared/netflow.o: src/netflow.cpp src/netflow.h src/packet.h src/common.h
	g++ -g -c -fPIC src/netflow.cpp -o obj/shared/netflow.o

obj/static/netflow.o: src/netflow.cpp src/netflow.h src/packet.h src/common.h
	g++ -g -c src/netflow.cpp -o obj/static/netflow.o

obj/shared/packet.o: src/packet.cpp src/packet.h src/common.h
	g++ -g -c -fPIC src/packet.cpp -o obj/shared/packet.o

obj/static/packet.o: src/packet.cpp src/packet.h src/common.h
	g++ -g -c src/packet.cpp -o obj/static/packet.o

obj/shared/pcap.o: src/pcap.cpp src/pcap.h src/packet.h src/common.h
	g++ -g -c -fPIC src/pcap.cpp -o obj/shared/pcap.o

obj/static/pcap.o: src/pcap.cpp src/pcap.h src/packet.h src/common.h
	g++ -g -c src/pcap.cpp -o obj/static/pcap.o

obj/shared/process.o: src/process.cpp src/process.h
	g++ -g -c -fPIC src/process.cpp -o obj/shared/process.o

obj/static/process.o: src/process.cpp src/process.h
	g++ -g -c src/process.cpp -o obj/static/process.o

obj/shared/sqlitedb.o: src/sqlitedb.cpp src/sqlitedb.h src/common.h
	g++ -g -c -fPIC src/sqlitedb.cpp -o obj/shared/sqlitedb.o

obj/static/sqlitedb.o: src/sqlitedb.cpp src/sqlitedb.h src/common.h
	g++ -g -c src/sqlitedb.cpp -o obj/static/sqlitedb.o

obj/shared/tcpsocket.o: src/tcpsocket.cpp src/tcpsocket.h
	g++ -g -c -fPIC src/tcpsocket.cpp -o obj/shared/tcpsocket.o

obj/static/tcpsocket.o: src/tcpsocket.cpp src/tcpsocket.h
	g++ -g -c src/tcpsocket.cpp -o obj/static/tcpsocket.o

obj/shared/tcpserversocket.o: src/tcpserversocket.cpp src/tcpserversocket.h src/tcpsocket.h
	g++ -g -c -fPIC src/tcpserversocket.cpp -o obj/shared/tcpserversocket.o

obj/static/tcpserversocket.o: src/tcpserversocket.cpp src/tcpserversocket.h src/tcpsocket.h
	g++ -g -c src/tcpserversocket.cpp -o obj/static/tcpserversocket.o

obj/shared/udpsocket.o: src/udpsocket.cpp src/udpsocket.h src/udppacket.h
	g++ -g -c -fPIC src/udpsocket.cpp -o obj/shared/udpsocket.o

obj/static/udpsocket.o: src/udpsocket.cpp src/udpsocket.h src/udppacket.h
	g++ -g -c src/udpsocket.cpp -o obj/static/udpsocket.o

obj/shared/udppacket.o: src/udppacket.cpp src/udppacket.h
	g++ -g -c -fPIC src/udppacket.cpp -o obj/shared/udppacket.o

obj/static/udppacket.o: src/udppacket.cpp src/udppacket.h
	g++ -g -c src/udppacket.cpp -o obj/static/udppacket.o

obj/shared/inetaddress.o: src/inetaddress.cpp src/inetaddress.h
	g++ -g -c -fPIC src/inetaddress.cpp -o obj/shared/inetaddress.o

obj/static/inetaddress.o: src/inetaddress.cpp src/inetaddress.h
	g++ -g -c src/inetaddress.cpp -o obj/static/inetaddress.o

obj/shared/common.o: src/common.cpp src/common.h
	g++ -g -c -fPIC src/common.cpp -o obj/shared/common.o

obj/static/common.o: src/common.cpp src/common.h
	g++ -g -c src/common.cpp -o obj/static/common.o

obj/shared/ai.o: src/ai.cpp src/ai.h src/common.h
	g++ -g -c -fPIC src/ai.cpp -o obj/shared/ai.o

obj/static/ai.o: src/ai.cpp src/ai.h src/common.h
	g++ -g -c src/ai.cpp -o obj/static/ai.o

install:
	rm -fR /usr/include/utility
	rm -f /usr/lib/libutility.so /usr/lib/libutility.a
	mkdir /usr/include/utility
	cp src/*.h /usr/include/utility
	cp libutility.so libutility.a /usr/lib

clean:
	rm -f obj/shared/*.o obj/static/*.o libutility.so libutility.a

