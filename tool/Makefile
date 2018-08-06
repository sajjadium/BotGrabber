exe: netflow.exe pktcount.exe edittime.exe editpcap.exe scan2bin.exe dispatch.exe scan2str.exe

nfanalyzer: src/nfanalyzer.cpp
	g++ -g -o nfanalyzer src/nfanalyzer.cpp -lutility

editpcap.exe: src/editpcap.cpp
	g++ -g -o editpcap.exe src/editpcap.cpp -lutility -lpcap -lbz2

scan2bin.exe: src/scan2bin.cpp
	g++ -g -o scan2bin.exe src/scan2bin.cpp -lutility -lbz2

dispatch.exe: src/dispatch.cpp
	g++ -g -o dispatch.exe src/dispatch.cpp -lutility -lbz2 -lpcap

scan2str.exe: src/scan2str.cpp
	g++ -g -o scan2str.exe src/scan2str.cpp -lutility -lbz2

nftcpudp: src/nftcpudp.cpp
	g++ -g -o nftcpudp src/nftcpudp.cpp -lutility

nfselect: src/nfselect.cpp
	g++ -g -o nfselect src/nfselect.cpp -lutility

netflow.exe: src/netflow.cpp
	g++ -g -o netflow.exe src/netflow.cpp -lutility -lpcap -lbz2

pktcount.exe: src/pktcount.cpp
	g++ -g -o pktcount.exe src/pktcount.cpp -lutility -lpcap -lbz2

edittime.exe: src/edittime.cpp
	g++ -g -o edittime.exe src/edittime.cpp -lutility -lpcap -lbz2

nfcheck: src/nfcheck.cpp
	g++ -g -o nfcheck src/nfcheck.cpp -lutility -lpcap

sqlite2nf: src/sqlite2nf.cpp
	g++ -g -o sqlite2nf src/sqlite2nf.cpp -lutility -lpcap

nfi2d: src/nfi2d.cpp
	g++ -g -o nfi2d src/nfi2d.cpp -lutility

nfsq2my: src/nfsq2my.cpp
	g++ -g -o nfsq2my src/nfsq2my.cpp -lutility

nf2db: src/nf2db.cpp
	g++ -g -o nf2db src/nf2db.cpp -lutility

nfstr2bin: src/nfstr2bin.cpp
	g++ -g -o nfstr2bin src/nfstr2bin.cpp -lutility

nfbin2str: src/nfbin2str.cpp
	g++ -g -o nfbin2str src/nfbin2str.cpp -lutility -lpcap

nfsort: src/nfsort.cpp
	g++ -g -o nfsort src/nfsort.cpp -lutility

nfedit: src/nfedit.cpp
	g++ -g -o nfedit src/nfedit.cpp -lutility

mergepcap: src/mergepcap.cpp
	g++ -g -o mergepcap src/mergepcap.cpp -lutility -lbz2 -lpcap

clean:
	rm -f *.o *.exe

