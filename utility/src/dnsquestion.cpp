#include "dns.h"
#include "common.h"

#include <cstdio>
#include <cstring>

int readName(char *, char *, char **);

namespace utility {
	DnsQuestion::DnsQuestion() {
		memset(this, 0, sizeof(DnsQuestion));
	}

	DnsQuestion::~DnsQuestion() {
		if (this->name != NULL) {
			delete[] this->name;
			this->name = NULL;
		}
	}

	char *DnsQuestion::fill(const char *dns_data, char *cursor) {
		// read name
		int len = readName(dns_data, cursor, &this->name);
		if (len == -1)
			return NULL;
		str2lower(this->name);
		cursor += len;

		// read type
		this->type_id = readShort(cursor);
		if (!checkTypeId(this->type_id))
			return NULL;
		cursor += 2;

		//read class
		this->class_id = readShort(cursor);
		if (!checkClassId(this->class_id))
			return NULL;
		cursor += 2;

		return cursor;
	}

	string DnsQuestion::toString() {
		char temp[500];
		sprintf(temp, "Name: %s, Type: %s, Class: %s", this->name, getDnsRRType(this->type_id).c_str(), getDnsRRClass(this->class_id).c_str());
		return string(temp);
	}
}

