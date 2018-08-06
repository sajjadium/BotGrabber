#ifndef UTILITY_DNS_H
#define UTILITY_DNS_H

#include <string>
#include <deque>

using namespace std;

namespace utility {
	#define DNS_TYPE_A 0x0001
	#define DNS_TYPE_NS 0x0002
	#define DNS_TYPE_CNAME 0x0005
	#define DNS_TYPE_SOA 0x0006
	#define DNS_TYPE_PTR 0x000C
	#define DNS_TYPE_MX 0x000F
	#define DNS_TYPE_TXT 0x0010
	#define DNS_TYPE_AAAA 0x001C
	#define DNS_TYPE_SRV 0x0021
	#define DNS_TYPE_ANY 0x00FF

	#define DNS_CLASS_IN 0x0001

	#define DNS_REPLY_CODE(dns_msg) (((dns_msg)->flags) & 0x000F)

	#define DNS_REPLY_CODE_NO_ERROR 0
	#define DNS_REPLY_CODE_FORMAT_ERROR 1
	#define DNS_REPLY_CODE_SERVER_FAILURE 2
	#define DNS_REPLY_CODE_NAME_ERROR 3
	#define DNS_REPLY_CODE_NOT_IMPLEMENTED 3
	#define DNS_REPLY_CODE_REFUSED 5

	string getDnsRRType(unsigned short);
	string getDnsRRClass(unsigned short);
	int extractName(const char *, const char *, char *);
	int readName(const char *, const char *, char **);
	bool checkClassId(unsigned  short);
	bool checkTypeId(unsigned short);

	class DnsQuestion {
		public:
			char *name;
			unsigned short type_id;
			unsigned short class_id;

			DnsQuestion();
			~DnsQuestion();
			char *fill(const char *, char *);
			string toString();
	};

	class DnsRR_ {
		public:
			virtual ~DnsRR_();
			virtual string toString() = 0;
			virtual bool fill(const char *, const char *) = 0;
	};

	class DnsRR_A : public DnsRR_ {
		public:
			unsigned int addr;

			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_AAAA : public DnsRR_ {
		public:
			char addr[16];

			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_NS : public DnsRR_ {
		public:
			char *name_server;

			~DnsRR_NS();
			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_CNAME : public DnsRR_ {
		public:
			char *primary_name;

			~DnsRR_CNAME();
			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_SOA : public DnsRR_ {
		public:
			char *primary_name_server;
			char *email;
			unsigned int serial_number;
			unsigned int refresh_interval;
			unsigned int retry_interval;
			unsigned int expiration_limit;
			unsigned int min_ttl;

			~DnsRR_SOA();
			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_PTR : public DnsRR_ {
		public:
			char *domain_name;

			~DnsRR_PTR();
			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_MX : public DnsRR_ {
		public:
			unsigned short preference;
			char *mail_exchange;

			~DnsRR_MX();
			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR_TXT : public DnsRR_ {
		public:
			char *text;

			~DnsRR_TXT();
			bool fill(const char *, const char *);
			string toString();
	};

	class DnsRR {
		public:
			char *name;
			unsigned short type_id;
			unsigned short class_id;
			unsigned int ttl;
			unsigned short len;
			DnsRR_ *data;

			DnsRR();
			~DnsRR();
			char *fill(const char *, char *);
			string toString();
	};

	class DnsMessage {
		public:
			unsigned short id;
			unsigned short flags;
			unsigned short num_of_questions;
			unsigned short num_of_answer_rrs;
			unsigned short num_of_authority_rrs;
			unsigned short num_of_additional_rrs;

			DnsQuestion *questions;
			DnsRR *answer_rrs;
			DnsRR *authority_rrs;
			DnsRR *additional_rrs;

			DnsMessage();
			~DnsMessage();

			bool fill(const char *);
			deque<DnsRR *> *getAnswers(const char *);
			string toString();
	};

	class DomainName {
		public:
			char *full_name;
			char *top_level_domain;
			char *second_level_domain;
			char *third_level_domain;

			DomainName(const char *);
			~DomainName();

			bool fill();
			string getMainName();
			string getFullName();
	};
}

#endif

