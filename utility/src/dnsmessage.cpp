#include "dns.h"
#include "common.h"

#include <cstdio>
#include <cstring>

namespace utility {
	DnsMessage::DnsMessage() {
		memset(this, 0, sizeof(DnsMessage));
	}

	DnsMessage::~DnsMessage() {
		delete[] this->questions;
		delete[] this->answer_rrs;
		delete[] this->authority_rrs;
		delete[] this->additional_rrs;
	}

	bool DnsMessage::fill(const char *dns_data) {
		char *cursor = (char *)dns_data;

		this->id = readShort(dns_data);
		this->flags = readShort(dns_data + 2);
		this->num_of_questions = readShort(dns_data + 4);
		this->num_of_answer_rrs = readShort(dns_data + 6);
		this->num_of_authority_rrs = readShort(dns_data + 8);
		this->num_of_additional_rrs = readShort(dns_data + 10);

		this->questions = (this->num_of_questions > 0) ? new DnsQuestion[this->num_of_questions] : NULL;
		this->answer_rrs = (this->num_of_answer_rrs > 0) ? new DnsRR[this->num_of_answer_rrs] : NULL;
		this->authority_rrs = (this->num_of_authority_rrs > 0) ? new DnsRR[this->num_of_authority_rrs] : NULL;
		this->additional_rrs= (this->num_of_additional_rrs> 0) ? new DnsRR[this->num_of_additional_rrs] : NULL;

		cursor += 12;

		// read questions
		for (int i = 0; i < this->num_of_questions; i++)
			if ((cursor = this->questions[i].fill(dns_data, cursor)) == NULL)
				return false;

		// read answer RRs
		for (int i = 0; i < this->num_of_answer_rrs; i++)
			if ((cursor = this->answer_rrs[i].fill(dns_data, cursor)) == NULL)
				return false;

		// read authority RRs
		for (int i = 0; i < this->num_of_authority_rrs; i++)
			if ((cursor = this->authority_rrs[i].fill(dns_data, cursor)) == NULL)
				return false;

		// read authority RRs
		for (int i = 0; i < this->num_of_additional_rrs; i++)
			if ((cursor = this->additional_rrs[i].fill(dns_data, cursor)) == NULL)
				return false;

		return true;
	}

	deque<DnsRR *> *DnsMessage::getAnswers(const char *name) {
		deque<DnsRR *> *answers_ = new deque<DnsRR *>();

		for (int i = 0; i < this->num_of_answer_rrs; i++)
			if (strcmp(name, this->answer_rrs[i].name) == 0)
				answers_->push_back(&this->answer_rrs[i]);

		return answers_;
	}

	string DnsMessage::toString() {
		char temp[500];

		sprintf(temp, "Transaction ID: %x\nFlags: %x\nQuestions: %d\nAnswer RRs: %d\nAuthority RRs: %d\nAdditional RRs: %d\n",
				this->id,
				this->flags,
				this->num_of_questions,
				this->num_of_answer_rrs,
				this->num_of_authority_rrs,
				this->num_of_additional_rrs);

		string res(temp);

		// print quesries
		if (this->num_of_questions > 0) {
			res += "Queries:\n";
			for (int i = 0; i < this->num_of_questions; i++)
				res += this->questions[i].toString() + "\n";
		}

		// print answers
		if (this->num_of_answer_rrs > 0) {
			res += "Answers:\n";
			for (int i = 0; i < this->num_of_answer_rrs; i++)
				res += this->answer_rrs[i].toString() + "\n";
		}

		// print authority servers
		if (this->num_of_authority_rrs > 0) {
			res += "Authoritative Nameservers:\n";
			for (int i = 0; i < this->num_of_authority_rrs; i++)
				res += this->authority_rrs[i].toString() + "\n";
		}

		// print additional records
		if (this->num_of_additional_rrs > 0) {
			res += "Additional Records:\n";
			for (int i = 0; i < this->num_of_additional_rrs; i++)
				res += this->additional_rrs[i].toString() + "\n";
		}

		res += "------------------------------------------------------\n";

		return res;
	}
}

