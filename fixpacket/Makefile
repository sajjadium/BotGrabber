fixpacket: obj/fixpacket.o
	g++ -o fixpacket obj/fixpacket.o -lutility -lpcap

obj/fixpacket.o: src/fixpacket.cpp
	g++ -o obj/fixpacket.o -c src/fixpacket.cpp

install:
	sudo cp fixpacket /usr/local/bin

clean:
	rm -f obj/*.o fixpacket

