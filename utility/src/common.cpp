#include "common.h"
#include "packet.h"

#include <cstring>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <cctype>
#include <cstdio>

#include <algorithm>

#include <arpa/inet.h>

#include <dirent.h>

#include <bzlib.h>

using namespace std;

namespace utility {
	bool StringCompare::operator()(const char *str1, const char *str2) const {
		return (strcmp(str1, str2) < 0);
	}

	bool StringCompare::operator()(const string &str1, const string &str2) const {
		return (strcmp(str1.c_str(), str2.c_str()) < 0);
	}

	double pcapTime(const pcap_pkthdr *header) {
		return header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
	}

	Mac host2net(Mac mac) {
		Mac new_mac;

		new_mac.byte0 = mac.byte5;
		new_mac.byte1 = mac.byte4;
		new_mac.byte2 = mac.byte3;
		new_mac.byte3 = mac.byte2;
		new_mac.byte4 = mac.byte1;
		new_mac.byte5 = mac.byte0;

		return new_mac;
	}

	unsigned int host2net(unsigned int l) {
		return htonl(l);
	}

	unsigned short host2net(unsigned short s) {
		return htons(s);
	}

	Mac net2host(Mac mac) {
		return host2net(mac);
	}

	unsigned int net2host(unsigned int l) {
		return host2net(l);
	}

	unsigned short net2host(unsigned short s) {
		return host2net(s);
	}

	string int2str(int value) {
		char temp[50];
		sprintf(temp, "%d", value);
		return string(temp);
	}

	string long2str(long value) {
	}

	string float2str(float value) {
		return double2str((double)value);
	}

	string double2str(double value) {
		char temp[100];
		sprintf(temp, "%f", value);
		return string(temp);
	}

	string ip2str(unsigned int ip) {
		char str_ip[16];
		unsigned char *_ip = (unsigned char *)&ip;
		memset(str_ip, 0, 16);
		sprintf(str_ip, "%d.%d.%d.%d", _ip[3], _ip[2], _ip[1], _ip[0]);

		return string(str_ip);
	}

	string ip2str(const char *ip) {
		char str_ip[40];
		unsigned short *_ip = (unsigned short *)ip;
		memset(str_ip, 0, sizeof(str_ip));
		sprintf(str_ip, "%x:%x:%x:%x:%x:%x:%x:%x", net2host(_ip[7]),net2host( _ip[6]), net2host(_ip[5]), net2host(_ip[4]), net2host(_ip[3]), net2host(_ip[2]), net2host(_ip[1]), net2host(_ip[0]));

		return string(str_ip);
	}

	string mac2str(Mac mac) {
		char str_mac[18];

		sprintf(str_mac, "%x:%x:%x:%x:%x:%x", mac.byte5,
				mac.byte4,
				mac.byte3,
				mac.byte2,
				mac.byte1,
				mac.byte0);

		return string(str_mac);
	}

	short str2short(const char *value) {
		return atoi(value);
	}

	int str2int(const char *value) {
		return atoi(value);
	}

	long str2long(const char *value) {
	}

	float str2float(const char *value) {
		return (float)str2double(value);
	}

	double str2double(const char *value) {
		return atof(value);
	}

	unsigned int str2ip(const char *str_ip) {
		unsigned int decimal_ip = 0, p = 3, byte;

		char *str_ip_copy = strclone(str_ip);
		char *tok = strtok(str_ip_copy, ".");

		while (tok != NULL) {
			sscanf(tok, "%d", &byte);
			decimal_ip += byte * (unsigned int)pow(256, p);
			p --;

			tok = strtok(NULL, ".");
		}

		delete[] str_ip_copy;

		return decimal_ip;
	}

	Mac str2mac(const char *str_mac) {
		Mac mac;
		char *_mac = (char *)&mac;
		int byte, p = 5;
		char str_mac_copy[18];

		strcpy(str_mac_copy, str_mac);

		char *tok = strtok(str_mac_copy, ":");

		while (tok != NULL) {
			sscanf(tok, "%x", &byte);
			_mac[p] = byte;
			p --;

			tok = strtok(NULL, ":");
		}

		return mac;
	}

	unsigned short readShort(const char *data) {
		return net2host(*((unsigned short *)data));
	}

	unsigned int readInt(const char *data) {
		return net2host(*((unsigned int *)data));
	}

	char *readline(FILE *file) {
		char *line = NULL;

		char temp[1000];
		if (fgets(temp, sizeof(temp), file) != NULL) {
			temp[strlen(temp) - 1] = 0;
			line = strclone(temp);
		}

		return line;
	}

	unsigned short checksum (const char* data, unsigned short len) {
		unsigned short nleft = len;
		unsigned int sum = 0;
		unsigned short *w = (unsigned short *)data;
		unsigned short answer = 0;

		while (nleft > 1) {
			sum += *w++;
			nleft -= 2;
		}

		if (nleft == 1) {
			*(unsigned char*)(&answer) = *(unsigned char*)w;
			sum += answer;
		}

		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
		answer = ~sum;

		return answer;
	}

	char *strclone(const char *str) {
		if (str == NULL)
			return NULL;

		char *new_str = new char[strlen(str) + 1];
		strcpy(new_str, str);
		return new_str;
	}

	string strltrim(const char *str) {
		int i;
		for (i = 0; i < strlen(str); i++)
			if (str[i] != ' ')
				break;

		return string(str + i);
	}

	string strrtrim(const char *str) {
		char *_str = strclone(str);

		for (int i = strlen(_str) - 1; i >= 0; i--)
			if (_str[i] == ' ')
				_str[i] = 0;
			else
				break;

		return string(_str);
	}

	string strtrim(const char *str) {
		return strltrim(strrtrim(str).c_str());
	}

	char *memclone(const char *mem, int len) {
		char *new_mem = new char[len];
		memcpy(new_mem, mem, len);
		return new_mem;
	}

	char *str2lower(char *str) {
		for (int i = 0; i < strlen(str); i++)
			str[i] = tolower(str[i]);

		return str;
	}

	char *str2upper(char *str) {
		for (int i = 0; i < strlen(str); i++)
			str[i] = toupper(str[i]);

		return str;
	}

	deque<char *> *listDirectory(const char *dir_path) {
		deque<char *> *entries = new deque<char *>();
		struct dirent *entry = NULL;
		DIR *dir = opendir(dir_path);
		char file_path[200];
		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			strcpy(file_path, dir_path);
			if (file_path[strlen(file_path) - 1] != '/')
				strcat(file_path, "/");
			strcat(file_path, entry->d_name);

			entries->push_back(strclone(file_path));
		}

		closedir(dir);

		sort(entries->begin(), entries->end(), StringCompare());

		return entries;
	}

	deque<string> *getTokens(const char *str, const char *delim) {
		deque<string> *tokens = new deque<string>();

		char *str_ = strclone(str);

		char *tok = strtok(str_, delim);
		while (tok != NULL) {
			tokens->push_back(string(tok));
			tok = strtok(NULL, delim);
		}

		delete[] str_;

		return tokens;
	}

	double mean(const deque<double> *data) {
		double sum = 0;
		for (int i = 0; i < data->size(); i++)
			sum += data->at(i);
		return sum / data->size();
	}

	double stdev(const deque<double> *data) {
		double mean_ = mean(data);
		double sum = 0;
		for (int i = 0; i < data->size(); i++)
			sum += pow(data->at(i) - mean_, 2);
		return pow(sum / (data->size() - 1), 0.5);
	}

	double ncd(const char *x, unsigned int x_len, const char *y, unsigned int y_len) {
		int block_size_100k = 1;
		int verbosity = 0;
		int work_factor = 0;
		int ret;

		// C(x)
		unsigned int x_dest_len = 2 * x_len + 600;
		char *x_dest = new char[x_dest_len];
		ret = BZ2_bzBuffToBuffCompress(x_dest, &x_dest_len, (char *)x, x_len, block_size_100k, verbosity, work_factor);
		delete[] x_dest;

		if (ret != BZ_OK) {
			printf("%s\n", ncdErrorMsg(ret).c_str());
			return -1;
		}

		// C(y)
		unsigned int y_dest_len = 2 * y_len + 600;
		char *y_dest = new char[y_dest_len];
		ret = BZ2_bzBuffToBuffCompress((char *)y_dest, &y_dest_len, (char *)y, y_len, block_size_100k, verbosity, work_factor);
		delete[] y_dest;

		if (ret != BZ_OK) {
			printf("%s\n", ncdErrorMsg(ret).c_str());
			return -1;
		}

		// C(xy)
		unsigned int xy_len = x_len + y_len;
		char *xy = new char[xy_len];
		memcpy(xy, x, x_len);
		memcpy(xy + x_len, y, y_len);
		unsigned int xy_dest_len = 2 * xy_len + 600;
		char *xy_dest = new char[xy_dest_len];
		ret = BZ2_bzBuffToBuffCompress(xy_dest, &xy_dest_len, xy, xy_len, block_size_100k, verbosity, work_factor);
		delete[] xy;
		delete[] xy_dest;

		if (ret != BZ_OK) {
			printf("%s\n", ncdErrorMsg(ret).c_str());
			return -1;
		}

		unsigned int c_xy, min_c_x_y, max_c_x_y;

		c_xy = xy_dest_len;

		if (x_dest_len <= y_dest_len) {
			min_c_x_y = x_dest_len;
			max_c_x_y = y_dest_len;
		} else {
			min_c_x_y = y_dest_len;
			max_c_x_y = x_dest_len;
		}

		return (c_xy - min_c_x_y) / (double)max_c_x_y;
	}

	string ncdErrorMsg(int ret) {
		string out_msg;

		switch (ret) {
			case BZ_CONFIG_ERROR:
				out_msg = "BZ_CONFIG_ERROR";
				break;

			case BZ_PARAM_ERROR:
				out_msg = "BZ_PARAM_ERROR";
				break;

			case BZ_MEM_ERROR:
				out_msg = "BZ_MEM_ERROR";
				break;

			case BZ_OUTBUFF_FULL:
				out_msg = "BZ_OUTBUFF_FULL";
				break;

			default:
				out_msg = "UNDEFINED";
		}

		return out_msg;
	}
}

