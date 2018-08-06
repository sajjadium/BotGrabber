/*
 * spp_ddos.c
 *
 * Copyright (C) 2006-2009 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * This file is part of an example of a dynamically loadable preprocessor.
 *
 * NOTES:
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include <search.h>

#include "preprocids.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preproc_lib.h"
#include "sf_dynamic_preprocessor.h"
#include "debug.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"

#define GENERATOR_DDOS 256
#define TCP_TIMEOUT 10

#define TCP_IS_SYN(flags) ((flags & TCPHEADER_SYN) == TCPHEADER_SYN)
#define TCP_IS_ACK(flags) ((flags & TCPHEADER_ACK) == TCPHEADER_ACK)

typedef void (*Free)(void *);

typedef struct _ListEntry {
	void *data;
	struct _ListEntry *next;
	struct _ListEntry *prev;
} ListEntry;

typedef struct _List {
	ListEntry *first;
	ListEntry *last;
	u_int32_t size;
} List;

typedef struct _TreeNode {
	void *data;
	struct _TreeNode *left;
	struct _TreeNode *right;
} TreeNode;

typedef struct _Connection {
	u_int8_t proto;
	u_int32_t src_ip;
	u_int16_t src_port;
	u_int32_t dst_ip;
	u_int16_t dst_port;

} Connection;

typedef struct _TableEntry {
	Connection conn;
	void *data;

} TableEntry;

typedef struct _IcmpTE {
	u_int32_t num_of_pings;
	u_int32_t num_of_bytes;
	List *pings_arrival;

} IcmpTE;

typedef struct _TcpConnState {
	u_int16_t src_port;
	double arrival_time;
} TcpConnState;

typedef struct _TcpTE {
	void *syns;
	u_int32_t num_of_syn_attacks;

} TcpTE;

typedef struct _UdpTE {
	u_int32_t num_of_pkts;
	u_int32_t num_of_bytes;
	List *pkts_arrival;

} UdpTE;

typedef struct _DDoSConfig {
	double tw_size;
	double last_tw_begin;
	void *conn_table;

} DDoSConfig;

tSfPolicyUserContextId ex_config = NULL;
DDoSConfig *ex_eval_config = NULL;
#ifdef SNORT_RELOAD
tSfPolicyUserContextId ex_swap_config = NULL;
#endif

extern DynamicPreprocessorData _dpd;

static void DDoSInit(char *);
static void DDoSProcess(void *, void *);
static DDoSConfig * DDoSParse(char *);
#ifdef SNORT_RELOAD
static void DDoSReload(char *);
static int DDoSReloadSwapPolicyFree(tSfPolicyUserContextId, tSfPolicyId, void *);
static void * DDoSReloadSwap(void);
static void DDoSReloadSwapFree(void *);
#endif

List *ListCreate() {
	List *list = malloc(sizeof(List));
	memset(list, 0, sizeof(List));
	return list;
}

void ListInsert(List *list, void *data) {
	ListEntry *le = (ListEntry *)malloc(sizeof(ListEntry));
	memset(le, 0, sizeof(ListEntry));

	le->data = data;

	if (list->first == NULL)
		list->first = list->last = le;
	else {
		list->last->next = le;
		le->prev = list->last;
		list->last = le;
	}

	list->size += 1;
}

void ListRemove(List *list, ListEntry *le, Free free_data) {
	if (le->prev == NULL)
		list->first = le->next;
	else
		le->prev->next = le->next;

	if (le->next == NULL)
		list->last = le->prev;
	else
		le->next->prev = le->prev;

	free_data(le->data);
	free(le);

	list->size -= 1;
}

void ListDestroy(List *list, Free free_data) {
	ListEntry *le = list->first;
	while (le != NULL) {
		ListEntry *next_le = le->next;

		if (free_data != NULL)
			free_data(le->data);
		free(le);

		le = next_le;
	}

	free(list);
}

void TreeWalk(TreeNode *root, List *list) {
	if (root == NULL)
		return;

	TreeWalk(root->left, list);
	ListInsert(list, root->data);
	TreeWalk(root->right, list);
}

void FreeUdpTE(void *ute) {
	ListDestroy(((UdpTE *)ute)->pkts_arrival, free);
	free(ute);
}

int CompareTableEntry(const void *n1, const void *n2) {
	return memcmp(n1, n2, sizeof(Connection));
}

int CompareTcpConnState(const void *n1, const void *n2) {
	return memcmp(n1, n2, sizeof(u_int16_t));
}

void *FindTableEntry(DDoSConfig *config, u_int8_t proto, u_int32_t src_ip, u_int16_t src_port, u_int32_t dst_ip, u_int16_t dst_port, u_int8_t not_insert) {
	Connection conn;
	memset(&conn, 0, sizeof(Connection));
	conn.proto = proto;
	conn.src_ip = src_ip;
	conn.src_port = src_port;
	conn.dst_ip = dst_ip;
	conn.dst_port = dst_port;

	TableEntry *te = NULL;

	TreeNode *ret = (TreeNode *)tfind(&conn, &config->conn_table, CompareTableEntry);
	if (ret == NULL) {
		if (!not_insert) {
			te = malloc(sizeof(TableEntry));
			memset(te, 0, sizeof(TableEntry));
			memcpy(&te->conn, &conn, sizeof(Connection));

			size_t _te_size = 0;
			if (proto == 1)
				_te_size = sizeof(IcmpTE);
			else if (proto == 6)
				_te_size = sizeof(TcpTE);
			else if (proto == 17)
				_te_size = sizeof(UdpTE);

			te->data = malloc(_te_size);
			memset(te->data, 0, _te_size);

			tsearch(te, &config->conn_table, CompareTableEntry);
		}
	} else
		te = (TableEntry *)ret->data;

	return te;
}

void ProcessTE(const void *nodep, const VISIT which, const int depth) {
	if (which == postorder || which == leaf) {
		sfPolicyUserPolicySet(ex_config, _dpd.getRuntimePolicy());
		DDoSConfig *config = (DDoSConfig *)sfPolicyUserDataGetCurrent(ex_config);
		if (config == NULL)
			return;

		TableEntry *te = (TableEntry *)((TreeNode *)nodep)->data;

		char src_ip[20], dst_ip[20];
		struct in_addr src_addr, dst_addr;
		src_addr.s_addr = te->conn.src_ip;
		dst_addr.s_addr = te->conn.dst_ip;
		strcpy(src_ip, inet_ntoa(src_addr));
		strcpy(dst_ip, inet_ntoa(dst_addr));

		char temp[200];

		if (te->conn.proto == 1) {
			IcmpTE *ite = (IcmpTE *)te->data;

			// calculate mean
			ListEntry *le = ite->pings_arrival->first->next;
			double mean = 0;
			while (le != NULL) {
				ListEntry *le1 = le->prev;
				double inter_arrival_time = *(double *)le->data - *(double *)le1->data;
				mean += inter_arrival_time;

				le = le->next;
			}
			mean /= ite->num_of_pings - 1;

			// calculate std
			le = ite->pings_arrival->first->next;
			double std = 0;
			while (le != NULL) {
				ListEntry *le1 = le->prev;
				double inter_arrival_time = *(double *)le->data - *(double *)le1->data;
				std += pow(inter_arrival_time - mean, 2);

				le = le->next;
			}
			std /= ite->num_of_pings - 1;
			std = pow(std, 0.5);

			sprintf(temp, "ICMP\t%s -> %s\tNum. Pings = %d, Num. Bytes = %d, Avg. BPP = %f, Ping Arrival STD = %f",
					src_ip,
					dst_ip, 
					ite->num_of_pings,
					ite->num_of_bytes,
					(double)ite->num_of_bytes / ite->num_of_pings,
					std);
			printf("%s\n", temp);
		} else if (te->conn.proto == 6) {
			TcpTE *tte = (TcpTE *)te->data;

			List *conns = ListCreate();
			TreeWalk(tte->syns, conns);
			ListEntry *le = conns->first;
			while (le != NULL) {
				TcpConnState *tcs = (TcpConnState *)le->data;
				if (config->last_tw_begin - tcs->arrival_time >= TCP_TIMEOUT) {
					tte->num_of_syn_attacks += 1;
					tdelete(tcs, &tte->syns, CompareTcpConnState);
					free(tcs);
				}

				le = le->next;
			}
			ListDestroy(conns, NULL);

			sprintf(temp, "TCP\t%s -> %s:%u\tNum. SYN Attacks = %d", src_ip, dst_ip, ntohs(te->conn.dst_port), tte->num_of_syn_attacks);
			printf("%s\n", temp);
		} else if (te->conn.proto == 17) {
			UdpTE *ute = (UdpTE *)te->data;

			// calculate mean
			ListEntry *le = ute->pkts_arrival->first->next;
			double mean = 0;
			while (le != NULL) {
				ListEntry *le1 = le->prev;
				double inter_arrival_time = *(double *)le->data - *(double *)le1->data;
				mean += inter_arrival_time;

				le = le->next;
			}
			mean /= ute->num_of_pkts - 1;

			// calculate std
			le = ute->pkts_arrival->first->next;
			double std = 0;
			while (le != NULL) {
				ListEntry *le1 = le->prev;
				double inter_arrival_time = *(double *)le->data - *(double *)le1->data;
				std += pow(inter_arrival_time - mean, 2);

				le = le->next;
			}
			std /= ute->num_of_pkts - 1;
			std = pow(std, 0.5);

			sprintf(temp, "UDP\t%s -> %s:%u\tNum. Pkts = %d, Num. Bytes = %d, Avg. BPP = %f, Pkt Arrival STD = %f",
					src_ip,
					dst_ip, 
					ntohs(te->conn.dst_port),
					ute->num_of_pkts,
					ute->num_of_bytes,
					(double)ute->num_of_bytes / ute->num_of_pkts,
					std);
			printf("%s\n", temp);
			//_dpd.alertAdd(GENERATOR_DDOS, 100, 1, 0, 3, temp, 0);
		}
	}
}

void DDoSExit(int signal, void *data) {
    sfPolicyUserPolicySet(ex_config, _dpd.getRuntimePolicy());
    DDoSConfig *config = (DDoSConfig *)sfPolicyUserDataGetCurrent(ex_config);
    if (config == NULL)
        return;

	twalk(config->conn_table, ProcessTE);
}

void DDoSSetup(void)
{
#ifndef SNORT_RELOAD
	_dpd.registerPreproc("ddos", DDoSInit);
#else
	_dpd.registerPreproc("ddos", DDoSInit, DDoSReload,
			DDoSReloadSwap, DDoSReloadSwapFree);
#endif

	DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: DDoS is setup\n"););
}

static void DDoSInit(char *args)
{
	DDoSConfig *config;
	tSfPolicyId policy_id = _dpd.getParserPolicy();

	_dpd.logMsg("DDoS dynamic preprocessor configuration\n");

	if (ex_config == NULL)
	{
        ex_config = sfPolicyConfigCreate();
        if (ex_config == NULL)
            _dpd.fatalMsg("Could not allocate configuration struct.\n");
    }

    config = DDoSParse(args);
    sfPolicyUserPolicySet(ex_config, policy_id);
    sfPolicyUserDataSetCurrent(ex_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(DDoSProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__ICMP | PROTO_BIT__TCP | PROTO_BIT__UDP);
    _dpd.addPreprocExit(DDoSExit, NULL, PRIORITY_LAST, PP_DDOS);

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: DDoS is initialized\n"););
}

static DDoSConfig * DDoSParse(char *args)
{
    char *arg;
    DDoSConfig *config = (DDoSConfig *)calloc(1, sizeof(DDoSConfig));

    if (config == NULL)
        _dpd.fatalMsg("Could not allocate configuration struct.\n");

    arg = strtok(args, " \t\n\r");
    if(!strcasecmp("tw_size", arg))
    {
        arg = strtok(NULL, " \t\n\r");
        if (!arg)
        {
            _dpd.fatalMsg("DDoSPreproc: Missing time window size\n");
        }

        config->tw_size = atof(arg);
        if (config->tw_size < 0)
        {
            _dpd.fatalMsg("DDoSPreproc: Invalid time window size %d\n", config->tw_size);
        }
		
		config->last_tw_begin = -1;
		config->conn_table = NULL;

        _dpd.logMsg("    Time Window Size: %f", config->tw_size);
    }
    else
    {
        _dpd.fatalMsg("DDoSPreproc: Invalid option %s\n", arg);
    }

    return config;
}

void DDoSProcess(void *pkt, void *context)
{
    SFSnortPacket *p = (SFSnortPacket *)pkt;
    DDoSConfig *config;

    sfPolicyUserPolicySet(ex_config, _dpd.getRuntimePolicy());
    config = (DDoSConfig *)sfPolicyUserDataGetCurrent(ex_config);
    if (config == NULL)
        return;

//    if (!p->ip4_header /*|| p->ip4_header->proto != IPPROTO_TCP || !p->tcp_header*/)
//    {
        /* Not for me, return */
//        return;
//    }

	double p_time = p->pcap_header->ts.tv_sec + p->pcap_header->ts.tv_usec / 1000000.0;
	if (config->last_tw_begin == -1)
		config->last_tw_begin = p_time;

	if (p_time - config->last_tw_begin >= config->tw_size) {
		config->last_tw_begin = p_time;

		// twalk(udp_table, ProcessUdpTE);

		// tdestroy(udp_table, FreeUdpTE);
	}

	if (p->ip4_header == NULL)
		return;

	u_int32_t src_ip = p->ip4_header->source.s_addr;
	u_int32_t dst_ip = p->ip4_header->destination.s_addr;

	if (p->icmp_header != NULL) {
		if (p->icmp_header->code == 0 && p->icmp_header->type == ICMP_ECHO_REQUEST) {
			TableEntry *te = (TableEntry *)FindTableEntry(config, 1, src_ip, 0, dst_ip, 0, 0);
			IcmpTE *ite = (IcmpTE *)te->data;

			if (ite->pings_arrival == NULL)
				ite->pings_arrival = ListCreate();

			ite->num_of_pings += 1;
			ite->num_of_bytes += p->payload_size;
			double *arrival_time = (double *)malloc(sizeof(double));
			*arrival_time = p_time;
			ListInsert(ite->pings_arrival, arrival_time);
		}
	} else if (p->tcp_header != NULL) {
		if (TCP_IS_SYN(p->tcp_header->flags) && TCP_IS_ACK(p->tcp_header->flags)) {
			TableEntry *te = (TableEntry *)FindTableEntry(config, 6, dst_ip, 0, src_ip, p->tcp_header->source_port, 0);
			TcpTE *tte = (TcpTE *)te->data;

			TreeNode *ret = (TreeNode *)tfind(&p->tcp_header->destination_port, &tte->syns, CompareTcpConnState);
			if (ret == NULL) {
				TcpConnState *tcs = (TcpConnState *)malloc(sizeof(TcpConnState));
				memset(tcs, 0, sizeof(TcpConnState));

				tcs->src_port = p->tcp_header->destination_port;
				tcs->arrival_time = p_time;

				tsearch(tcs, &tte->syns, CompareTcpConnState);
			} else {
				TcpConnState *tcs = (TcpConnState *)ret->data;
				tcs->arrival_time = p_time;
				tte->num_of_syn_attacks++;
			}
		} else if (!TCP_IS_SYN(p->tcp_header->flags) && TCP_IS_ACK(p->tcp_header->flags)) {
			TableEntry *te = (TableEntry *)FindTableEntry(config, 6, src_ip, 0, dst_ip, p->tcp_header->destination_port, 1);
			if (te != NULL) {
				TcpTE *tte = (TcpTE *)te->data;

				TreeNode *ret = (TreeNode *)tfind(&p->tcp_header->source_port, &tte->syns, CompareTcpConnState);
				if (ret != NULL) {
					TcpConnState *tcs = *(TcpConnState **)ret;
					tdelete(tcs, &tte->syns, CompareTcpConnState);
					free(tcs);
				}
			}
		}
	} else if (p->udp_header != NULL) {
		TableEntry *te = (TableEntry *)FindTableEntry(config, 17, src_ip, 0, dst_ip, p->udp_header->destination_port, 0);
		UdpTE *ute = (UdpTE *)te->data;

		if (ute->pkts_arrival == NULL)
			ute->pkts_arrival = ListCreate();

		ute->num_of_pkts += 1;
		ute->num_of_bytes += p->payload_size;
		double *arrival_time = (double *)malloc(sizeof(double));
		*arrival_time = p_time;
		ListInsert(ute->pkts_arrival, arrival_time);
	}
}

#ifdef SNORT_RELOAD
static void DDoSReload(char *args)
{
    DDoSConfig *config;
    tSfPolicyId policy_id = _dpd.getParserPolicy();

    _dpd.logMsg("DDoS preprocessor configuration\n");

    if (ex_swap_config == NULL)
    {
        ex_swap_config = sfPolicyConfigCreate();
        if (ex_swap_config == NULL)
            _dpd.fatalMsg("Could not allocate configuration struct.\n");
    }

    config = DDoSParse(args);
    sfPolicyUserPolicySet(ex_swap_config, policy_id);
    sfPolicyUserDataSetCurrent(ex_swap_config, config);

    /* Register the preprocessor function, Transport layer, ID 10000 */
    _dpd.addPreproc(DDoSProcess, PRIORITY_TRANSPORT, 10000, PROTO_BIT__TCP | PROTO_BIT__UDP);

    DEBUG_WRAP(_dpd.debugMsg(DEBUG_PLUGIN, "Preprocessor: DDoS is initialized\n"););
}

static int DDoSReloadSwapPolicyFree(tSfPolicyUserContextId config, tSfPolicyId policyId, void *data)
{
    DDoSConfig *policy_config = (DDoSConfig *)data;

    sfPolicyUserDataClear(config, policyId);
    free(policy_config);
    return 0;
}

static void * DDoSReloadSwap(void)
{
    tSfPolicyUserContextId old_config = ex_config;

    if (ex_swap_config == NULL)
        return NULL;

    ex_config = ex_swap_config;
    ex_swap_config = NULL;

    return (void *)old_config;
}

static void DDoSReloadSwapFree(void *data)
{
    tSfPolicyUserContextId config = (tSfPolicyUserContextId)data;

    if (data == NULL)
        return;

    sfPolicyUserDataIterate(config, DDoSReloadSwapPolicyFree);
    sfPolicyConfigDelete(config);
}
#endif

