netflow: obj/netflow.o
	g++ -o netflow obj/netflow.o -lutility -lpcap

obj/netflow.o: src/netflow.cpp src/netflow.h
	g++ -c src/netflow.cpp -o obj/netflow.o

install:
	cp netflow /usr/local/bin

clean:
	rm -f obj/*.o netflow

