#include "dns.h"
#include "common.h"

#include <cstring>
#include <cstdio>

namespace utility {
	string getDnsRRType(unsigned short type_id) {
		switch (type_id) {
			case DNS_TYPE_A:
				return string("A");

			case DNS_TYPE_NS:
				return string("NS");

			case DNS_TYPE_CNAME:
				return string("CNAME");

			case DNS_TYPE_SOA:
				return string("SOA");

			case DNS_TYPE_PTR:
				return string("PTR");

			case DNS_TYPE_MX:
				return string("MX");

			case DNS_TYPE_TXT:
				return string("TXT");

			case DNS_TYPE_AAAA:
				return string("AAAA");

			case DNS_TYPE_SRV:
				return string("SRV");

			case DNS_TYPE_ANY:
				return string("ANY");
		}
	}

	string getDnsRRClass(unsigned short class_id) {
		switch (class_id) {
			case DNS_CLASS_IN:
				return string("IN");
		}
	}

	int extractName(const char *dns_data, const char *name, char *final_name) {
		unsigned int fn_index = 0, name_index = 0;

		while (true) {
			unsigned char byte = name[name_index++];

			if (byte == 0) {
				break;
			}

			if ((byte & 0xC0) == 0) {
				for (int i = 0; i < byte; i ++)
					final_name[fn_index++] = name[name_index++];
				final_name[fn_index++] = '.';
			} else if (byte == 0xC0) {
				unsigned short offset = readShort(name + name_index - 1);
				offset &= 0x03FF;
				if (extractName(dns_data, dns_data + offset, final_name + fn_index) == -1)
					return -1;
				name_index ++;

				break;
			} else {
				return -1;
			}
		}

		return name_index;
	}

	int readName(const char *dns_data, const char *cursor, char **name) {
		char temp[300];

		memset(temp, 0, 300);
		int len = extractName(dns_data, cursor, temp);
		if (len == -1)
			return -1;
		temp[strlen(temp) - 1] = 0;
		*name = strclone(temp);

		return len;
	}

	bool checkTypeId(unsigned short type_id) {
		switch (type_id) {
			case DNS_TYPE_A:
			case DNS_TYPE_AAAA:
			case DNS_TYPE_NS:
			case DNS_TYPE_CNAME:
			case DNS_TYPE_SOA:
			case DNS_TYPE_PTR:
			case DNS_TYPE_MX:
			case DNS_TYPE_TXT:
				return true;

			default:
				return false;
		}
	}

	bool checkClassId(unsigned short class_id) {
		switch (class_id) {
			case DNS_CLASS_IN:
				return true;
			default:
				return false;
		}
	}
}

