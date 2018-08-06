#include "dns.h"
#include "common.h"

#include <cstdio>
#include <cstring>

namespace utility {
	/*************** DnsRR_ ****************/
	DnsRR_::~DnsRR_() {
	}

	/************** DnsRR_A *****************/
	bool DnsRR_A::fill(const char *dns_data, const char *cursor) {
		// read address
		this->addr = readInt(cursor);

		return true;
	}

	string DnsRR_A::toString() {
		char temp[500];
		sprintf(temp, "Addr: %s", ip2str(this->addr).c_str());
		return string(temp);
	}

	/************** DnsRR_AAAA *****************/
	bool DnsRR_AAAA::fill(const char *dns_data, const char *cursor) {
		// read address
		memcpy(this->addr, cursor, 16);

		return true;
	}

	string DnsRR_AAAA::toString() {
		char temp[500];
		sprintf(temp, "Addr: %s", ip2str(this->addr).c_str());
		return string(temp);
	}

	/*************** DnsRR_NS ****************/
	DnsRR_NS::~DnsRR_NS() {
		delete[] this->name_server;
	}

	bool DnsRR_NS::fill(const char *dns_data, const char *cursor) {
		// read name server
		if (readName(dns_data, cursor, &this->name_server) == -1)
			return false;

		str2lower(this->name_server);

		return true;
	}

	string DnsRR_NS::toString() {
		char temp[500];
		sprintf(temp, "Name Server: %s", this->name_server);
		return string(temp);
	}

	/**************** DnsRR_CNAME ******************/
	DnsRR_CNAME::~DnsRR_CNAME() {
		delete[] this->primary_name;
	}

	bool DnsRR_CNAME::fill(const char *dns_data, const char *cursor) {
		// read primary name
		if (readName(dns_data, cursor, &this->primary_name) == -1)
			return false;

		str2lower(this->primary_name);

		return true;
	}

	string DnsRR_CNAME::toString() {
		char temp[500];
		sprintf(temp, "Primary Name: %s", this->primary_name);
		return string(temp);
	}

	/**************** DnsRR_SOA *******************/
	DnsRR_SOA::~DnsRR_SOA() {
		delete[] this->primary_name_server;
		delete[] this->email;
	}

	bool DnsRR_SOA::fill(const char *dns_data, const char *cursor) {
		char *my_cursor = (char *)cursor;
		// read primary name
		int ret = readName(dns_data, my_cursor, &this->primary_name_server);
		if (ret == -1)
			return false;
		str2lower(this->primary_name_server);
		my_cursor += ret;
		// read email
		ret = readName(dns_data, my_cursor, &this->email);
		if (ret == -1)
			return false;
		str2lower(this->email);
		my_cursor += ret;
		// read serial number
		this->serial_number = readInt(my_cursor);
		my_cursor += 4;
		// read refresh interval
		this->refresh_interval = readInt(my_cursor);
		my_cursor += 4;
		// read retry interval
		this->retry_interval = readInt(my_cursor);
		my_cursor += 4;
		// read expiration limit
		this->expiration_limit = readInt(my_cursor);
		my_cursor += 4;
		// read min ttl
		this->min_ttl = readInt(my_cursor);
		my_cursor += 4;

		return true;
	}

	string DnsRR_SOA::toString() {
		char temp[500];
		sprintf(temp, "Primary Nameserver: %s, Email: %s, Serial Number: %d, Refresh Interval: %d, Retry Interval: %d, Expiration Limit: %d, Min. TTL: %d",
				this->primary_name_server,
				this->email,
				this->serial_number,
				this->refresh_interval,
				this->retry_interval,
				this->expiration_limit,
				this->min_ttl);
		return string(temp);
	}

	/***************** DnsRR_PTR ******************/
	DnsRR_PTR::~DnsRR_PTR() {
		delete[] this->domain_name;
	}

	bool DnsRR_PTR::fill(const char *dns_data, const char *cursor) {
		// read domain name
		if (readName(dns_data, cursor, &this->domain_name) == -1)
			return false;

		str2lower(this->domain_name);

		return true;
	}

	string DnsRR_PTR::toString() {
		char temp[500];
		sprintf(temp, "Domain Name: %s", this->domain_name);
		return string(temp);
	}

	/**************** DnsRR_MX *******************/
	DnsRR_MX::~DnsRR_MX() {
		delete[] this->mail_exchange;
	}

	bool DnsRR_MX::fill(const char *dns_data, const char *cursor) {
		char *my_cursor = (char *)cursor;
		// read preference
		this->preference = readShort(my_cursor);
		my_cursor += 2;
		// read mail exchange
		if (readName(dns_data, my_cursor, &this->mail_exchange) == -1)
			return false;

		str2lower(this->mail_exchange);

		return true;
	}

	string DnsRR_MX::toString() {
		char temp[500];
		sprintf(temp, "Preference: %d, Mail Exchange: %s", this->preference, this->mail_exchange);
		return string(temp);
	}

	/**************** DnsRR_TXT ******************/
	DnsRR_TXT::~DnsRR_TXT() {
		delete[] this->text;
	}

	bool DnsRR_TXT::fill(const char *dns_data, const char *cursor) {
		// read text
		if (readName(dns_data, cursor, &this->text) == -1)
			return false;

		return true;
	}

	string DnsRR_TXT::toString() {
		char temp[500];
		sprintf(temp, "Text: %s", this->text);
		return string(temp);
	}

	/*************** DnsRR ******************/
	DnsRR::DnsRR() {
		memset(this, 0, sizeof(DnsRR));
	}

	DnsRR::~DnsRR() {
		delete[] this->name;

		if (this->data != NULL) {
			delete this->data;
			this->data = NULL;
		}
	}

	char *DnsRR::fill(const char *dns_data, char *cursor) {
		char temp[300];

		// read name
		int ret = readName(dns_data, cursor, &this->name);
		if (ret == -1)
			return NULL;
		str2lower(this->name);
		cursor += ret;

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

		//read ttl
		this->ttl = readInt(cursor);
		cursor += 4;

		// read len
		this->len = readShort(cursor);
		cursor += 2;

		// read data
		switch (this->type_id) {
			case DNS_TYPE_A:
				this->data = new DnsRR_A();
				break;

			case DNS_TYPE_AAAA:
				this->data = new DnsRR_AAAA();
				break;

			case DNS_TYPE_NS:
				this->data = new DnsRR_NS();
				break;

			case DNS_TYPE_CNAME:
				this->data = new DnsRR_CNAME();
				break;

			case DNS_TYPE_SOA:
				this->data = new DnsRR_SOA();
				break;

			case DNS_TYPE_PTR:
				this->data = new DnsRR_PTR();
				break;

			case DNS_TYPE_MX:
				this->data = new DnsRR_MX();
				break;

			case DNS_TYPE_TXT:
				this->data = new DnsRR_TXT();
				break;
		}

		if (!this->data->fill(dns_data, cursor))
			return NULL;

		cursor += this->len;

		return cursor;
	}

	string DnsRR::toString() {
		char temp[500];
		sprintf(temp, "Name: %s Type: %s, Class: %s, TTL: %d, Len: %d, %s",
				this->name,
				getDnsRRType(this->type_id).c_str(),
				getDnsRRClass(this->class_id).c_str(),
				this->ttl,
				this->len,
				this->data->toString().c_str());
		return string(temp);
	}
}

