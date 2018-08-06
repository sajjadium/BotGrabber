#include "pcap.h"
#include "packet.h"
#include "common.h"

#include <cstdio>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace utility {
	////////////// Pcap ////////////////
	Pcap::Pcap(const char *name, const char *filter_exp, int count) {
		memset(this, 0, sizeof(Pcap));

		this->name = strclone(name);
		this->filter_exp = strclone(filter_exp);
		this->count = count;
	}

	Pcap::~Pcap() {
		delete[] this->name;
		delete[] this->filter_exp;

		this->close();
	}

	bool Pcap::openOffline() {
		char errbuf[PCAP_ERRBUF_SIZE];

		if ((this->pcap_id = pcap_open_offline(name, errbuf)) == NULL) {
			fprintf(stderr, "Can't open file \"%s\" because: \"%s\"\n", name, errbuf);
			return false;
		}

		return this->applyFilter();
	}

	bool Pcap::openOnline() {
		char errbuf[PCAP_ERRBUF_SIZE];

		if ((this->pcap_id = pcap_open_live(name, 65536, 1, 0, errbuf)) == NULL) {
			printf("Pcap Error: can't open adapter \"%s\"\n", name);
			return false;
		}

		return this->applyFilter();
	}

	Packet *Pcap::nextPacket() {
		struct pcap_pkthdr header;

		if (this->count == 0)
			return NULL;

		if (this->count != -1)
			this->count--;

		char *frame = (char *)pcap_next(this->pcap_id, &header);
		if (frame == NULL)
			return NULL;

		return new Packet(&header, frame);
	}

	bool Pcap::applyFilter() {
		struct bpf_program fp;

		if (pcap_compile(this->pcap_id, &fp, filter_exp, 0, 0) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(this->pcap_id));
			return false;
		}

		if (pcap_setfilter(this->pcap_id, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(this->pcap_id));
			pcap_freecode(&fp);
			return false;
		}

		pcap_freecode(&fp);

		return true;
	}

	void Pcap::close() {
		if (this->pcap_id != NULL) {
			pcap_close(this->pcap_id);
			this->pcap_id = NULL;
		}
	}

	/////////////// PcapDump ////////////////
	PcapDump::PcapDump(FILE *dump_id) {
		memset(this, 0, sizeof(PcapDump));
		this->dump_id = dump_id;
	}

	PcapDump::PcapDump(const char *dump_filename) {
		memset(this, 0, sizeof(PcapDump));
		this->dump_filename = strclone(dump_filename);
	}

	PcapDump::~PcapDump() {
		if (this->dump_filename != NULL)
			delete[] this->dump_filename;

		this->close();
	}

	bool PcapDump::open() {
		if (this->dump_id == NULL) {
			this->dump_id = fopen(this->dump_filename, "w");

			if (this->dump_id == NULL) {
				fprintf(stderr, "Error opening file for dump\n");
				return false;
			}
		}

		this->writeGlobalHeader();

		return true;
	}

	void PcapDump::close() {
		if (this->dump_filename != NULL && this->dump_id != NULL) {
			fclose(this->dump_id);
			this->dump_id = NULL;
		}
	}

	void PcapDump::writeGlobalHeader() {
		struct pcap_file_header global_header;
		memset(&global_header, 0, sizeof(struct pcap_file_header));

		global_header.magic = 0xa1b2c3d4;
		global_header.version_major = 2;
		global_header.version_minor = 4;
		global_header.thiszone = 0;
		global_header.sigfigs = 0;
		global_header.snaplen = 65535;
		global_header.linktype = 1;

		fwrite(&global_header, sizeof(struct pcap_file_header), 1, this->dump_id);
		fflush(this->dump_id);
	}

	void PcapDump::dump(const Packet *packet) {
		this->dump(packet->header, packet->frame);
	}

	void PcapDump::dump(const struct pcap_pkthdr *header, const char *frame) {
		PcapPktHdr pph;
		pph.ts.tv_sec = header->ts.tv_sec;
		pph.ts.tv_usec = header->ts.tv_usec;
		pph.caplen = header->caplen;
		pph.len = header->len;

		fwrite(&pph, sizeof(struct PcapPktHdr), 1, this->dump_id);
		fwrite(frame, 1, header->caplen, this->dump_id);
		fflush(this->dump_id);
	}

	/////////////////// PcapStream ////////////////////////
	bool PcapPacketCompare::operator()(const PcapPacket &pp1, const PcapPacket &pp2) const {
		return (pp1.second->getTime() < pp2.second->getTime());
	}

	PcapStream::PcapStream(const char *data_path, const char *filter_exp, int count) {
		memset(this, 0, sizeof(PcapStream));

		this->data_path = strclone(data_path);
		this->filter_exp = strclone(filter_exp);
		this->count = count;
	}

	PcapStream::~PcapStream() {
		this->close();

		delete[] this->data_path;
		delete[] this->filter_exp;
	}

	bool PcapStream::open() {
		deque<char *> *file_list = NULL;

		struct stat data_stat;
		stat(this->data_path, &data_stat);

		if (S_ISDIR(data_stat.st_mode))
			file_list = listDirectory(this->data_path);
		else if (S_ISREG(data_stat.st_mode)) {
			file_list = new deque<char *>();
			file_list->push_back(strclone(this->data_path));
		} else
			return false;

		this->pcap_list = new deque<Pcap *>();
		this->pcap_pkts = new multiset<PcapPacket, PcapPacketCompare>();

		for (int i = 0; i < file_list->size(); i++) {
			Pcap *pcap = new Pcap(file_list->at(i), this->filter_exp, -1);
			if (pcap->openOffline()) {
				Packet *pkt = pcap->nextPacket();
				if (pkt != NULL) {
					this->pcap_list->push_back(pcap);
					this->pcap_pkts->insert(PcapPacket(this->pcap_list->size() - 1, pkt));
				} else
					delete pcap;
			} else
				delete pcap;

			delete[] file_list->at(i);
		}

		delete file_list;

		return true;
	}

	Packet *PcapStream::nextPacket() {
		if ((this->count == 0) || (this->pcap_pkts->size() == 0))
			return NULL;

		if (this->count != -1)
			this->count--;

		multiset<PcapPacket, PcapPacketCompare>::iterator pkt_it = this->pcap_pkts->begin();
		PcapPacket pcap_packet = *pkt_it;
		this->pcap_pkts->erase(pkt_it);

		Pcap *pcap_ = this->pcap_list->at(pcap_packet.first);
		Packet *packet = pcap_->nextPacket();
		if (packet != NULL) {
			this->pcap_pkts->insert(PcapPacket(pcap_packet.first, packet));
		} else {
			fprintf(stderr, "%s is completed.\n", pcap_->name);
			pcap_->close();
			delete pcap_;

			this->pcap_list->at(pcap_packet.first) = NULL;
		}

		return pcap_packet.second;
	}

	void PcapStream::close() {
		if (this->pcap_list != NULL) {
			for (int i = 0; i < this->pcap_list->size(); i++)
				delete this->pcap_list->at(i);

			delete this->pcap_list;
			this->pcap_list = NULL;
		}

		if (this->pcap_pkts != NULL) {
			multiset<PcapPacket, PcapPacketCompare>::iterator it = this->pcap_pkts->begin();
			while (it != this->pcap_pkts->end()) {
				Packet *pkt = (*it).second;
				this->pcap_pkts->erase(it++);
				delete pkt;
			}

			delete this->pcap_pkts;
			this->pcap_pkts = NULL;
		}
	}
}
	/*	pcap_t *pcap_id = NULL;
		pcap_if_t *alldevs = NULL;
		pcap_if_t *dev = NULL;
		int i = 0;
		char errbuf[PCAP_ERRBUF_SIZE];

	// Retrieve the device list
	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
	fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);

	return NULL;
	}

	for (dev = alldevs; dev; dev = dev->next)
	i++;

	if (*if_num == 0) {
	// Print the list 
	for (dev = alldevs; dev; dev = dev->next) {
	printf("%d. ", ++i);
	if (dev->description)
	printf("%s\n", dev->description);
	else
	printf(" (No description available)\n");
	}

	if (i == 0) {
	printf("\nNo interfaces found! Make sure libpcap is installed.\n");

	return NULL;
	}

	printf("Enter the interface number (1-%d):", i);

	scanf("%d", if_num);
	}

	if (*if_num < 1 || *if_num > i) {
	printf("\nInterface number out of range.\n");
// Free the device list 
pcap_freealldevs(alldevs);

return NULL;
}

Jump to the selected adapter 
for(dev = alldevs, i = 0; i < *if_num - 1; dev = dev->next, i++);

if ((pcap_id = pcap_open_live(name,	// name of the device
65536,			// portion of the packet to capture.
// 65536 grants that the whole packet will be captured on all the MACs.
1,				// promiscuous mode (nonzero means promiscuous)
0,				// read timeout
errbuf			// error buffer
)) == NULL) {
printf("Pcap Error: can't open adapter", name);
	// Free the device list 
	//		pcap_freealldevs(alldevs);

	return NULL;
	}
	 */

