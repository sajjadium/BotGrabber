all: botgrabber

analyzer: obj/analyzer.o
	g++ -o analyzer obj/analyzer.o -lutility -lsqlite3 -lpcap

botgrabber: obj/clustering.o obj/correlation.o obj/botgrabber.o obj/main.o
	g++ -g -o botgrabber obj/clustering.o obj/correlation.o obj/botgrabber.o obj/main.o -lutility -lsqlite3 -lpcap -lpcre -lbz2

obj/analyzer.o: src/analyzer.cpp
	g++ -g -c src/analyzer.cpp -o obj/analyzer.o

obj/main.o: src/main.cpp src/botgrabber.h
	g++ -g -c src/main.cpp -o obj/main.o

obj/clustering.o: src/clustering.cpp src/botgrabber.h
	g++ -g -c src/clustering.cpp -o obj/clustering.o

obj/correlation.o: src/correlation.cpp src/botgrabber.h
	g++ -g -c src/correlation.cpp -o obj/correlation.o

obj/botgrabber.o: src/botgrabber.cpp src/botgrabber.h
	g++ -g -c src/botgrabber.cpp -o obj/botgrabber.o

clean:
	rm -f obj/*.o botgrabber analyzer

