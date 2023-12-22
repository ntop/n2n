/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t
#include <stdio.h>                   // for sprintf
#include <stdlib.h>                  // for free, malloc, atoi
#include <string.h>                  // for memcpy, strcpy, NULL, memset
#include "n2n.h"                     // for filter_rule_t, filter_rule_pair_...
#include "network_traffic_filter.h"  // for create_network_traffic_filter
#include "uthash.h"                  // for UT_hash_handle, HASH_ITER, HASH_DEL

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>               // for inet_ntoa, inet_addr
#include <netinet/in.h>              // for in_addr, in_addr_t, ntohs, ntohl
#endif

// cache that hit less than 10 while 10000 package processed will be delete;
#define CLEAR_CACHE_EVERY_X_COUNT 10000
#define CLAER_CACHE_ACTIVE_COUNT  10

/* for [-Wmissing-declarations] */
const char* get_filter_packet_proto_name (filter_packet_proto proto);

const char* get_filter_packet_proto_name (filter_packet_proto proto) {

    switch(proto) {
        case FPP_ARP:
            return "ARP";
        case FPP_TCP:
            return "TCP";
        case FPP_UDP:
            return "UDP";
        case FPP_ICMP:
            return "ICMP";
        case FPP_IGMP:
            return "IGMP";
        default:
            return "UNKNOWN_PROTO";
    }
}


/* for [-Wmissing-declarations] */
const char* get_filter_packet_info_log_string (packet_address_proto_info_t* info);

const char* get_filter_packet_info_log_string (packet_address_proto_info_t* info) {

    static char buf[1024] = {0};

    switch(info->proto) {
        case FPP_ARP:
        case FPP_ICMP:
        case FPP_IGMP:
            return get_filter_packet_proto_name(info->proto);
        case FPP_TCP:
        case FPP_UDP: {
            struct in_addr src, dst;

            src.s_addr = info->src_ip;
            dst.s_addr = info->dst_ip;
            const char* proto = get_filter_packet_proto_name(info->proto);
            char src_ip[64] = {0};
            char dst_ip[64] = {0};
            strcpy(src_ip, inet_ntoa(src));
            strcpy(dst_ip, inet_ntoa(dst));
            sprintf(buf, "%s\t%s:%d->%s:%d", proto, src_ip, info->src_port, dst_ip, info->dst_port);
            return buf;
        }
        default:
            return "UNKNOWN_PROTO";
    }
}

/* for [-Wmissing-declarations] */
void collect_packet_info (packet_address_proto_info_t* out_info, unsigned char *buffer, int size);

void collect_packet_info (packet_address_proto_info_t* out_info, unsigned char *buffer, int size) {

    ether_hdr_t *hdr_ether = (ether_hdr_t*)buffer;
    uint16_t ether_type = ntohs(hdr_ether->type);
    struct n2n_iphdr *hdr_ip = NULL;
    struct n2n_tcphdr *hdr_tcp = NULL;
    struct n2n_udphdr *udp_hdr = NULL;

    memset(out_info, 0, sizeof(packet_address_proto_info_t));

    switch(ether_type) {
        case 0x0800: {
            buffer += sizeof(ether_hdr_t);
            size -= sizeof(ether_hdr_t);
            if(size <= 0) {
                return;
            }
            hdr_ip = (struct n2n_iphdr*)buffer;

            switch(hdr_ip->version) {
                case 4: {
                    out_info->src_ip = hdr_ip->saddr;
                    out_info->dst_ip = hdr_ip->daddr;
                    switch(hdr_ip->protocol) {
                        case 0x01:
                            out_info->proto = FPP_ICMP;
                            break;
                        case 0x02:
                            out_info->proto = FPP_IGMP;
                            break;
                        case 0x06: {
                            out_info->proto = FPP_TCP;
                            buffer += hdr_ip->ihl * 4;
                            size -= hdr_ip->ihl * 4;
                            if(size <= 0) {
                                return;
                            }
                            hdr_tcp = (struct n2n_tcphdr*)buffer;
                            out_info->src_port = ntohs(hdr_tcp->source);
                            out_info->dst_port = ntohs(hdr_tcp->dest);
                            break;
                        }
                        case 0x11: {
                            out_info->proto = FPP_UDP;
                            buffer += hdr_ip->ihl * 4;
                            size -= hdr_ip->ihl * 4;
                            if(size <= 0) {
                                return;
                            }
                            udp_hdr    = (struct n2n_udphdr*)buffer;
                            out_info->src_port = ntohs(udp_hdr->source);
                            out_info->dst_port = ntohs(udp_hdr->dest);
                            break;
                        }
                        default:
                            out_info->proto = FPP_UNKNOWN;
                        };
                        break;
                    }
                case 6: {
                    // TODO: IPV6 Not Support
                    out_info->proto = FPP_UNKNOWN;
                    break;
                }
                default:
                    out_info->proto = FPP_UNKNOWN;
                }
            break;
        }
    case 0x0806:
        out_info->proto = FPP_ARP;
        break;
    case 0x86DD:
        out_info->proto = FPP_UNKNOWN;
        break;
    default:
        traceEvent(TRACE_DEBUG, "collect_packet_info stumbled across the unknown ether type 0x%04X", ether_type);
    };
}

/* for [-Wmissing-declarations] */
const char* get_filter_rule_info_log_string (filter_rule_t* rule);

const char* get_filter_rule_info_log_string (filter_rule_t* rule) {

    static char buf[1024] = {0};
    char* print_start = buf;
    char src_net[64] = {0};
    char dst_net[64] = {0};
    struct in_addr src, dst;

    src.s_addr = rule->key.src_net_cidr;
    dst.s_addr = rule->key.dst_net_cidr;
    strcpy(src_net, inet_ntoa(src));
    strcpy(dst_net, inet_ntoa(dst));
    print_start += sprintf(print_start, "%s/%d:[%d,%d],%s/%d:[%d,%d]",
                           src_net, rule->key.src_net_bit_len,
                           rule->key.src_port_range.start_port, rule->key.src_port_range.end_port,
                           dst_net, rule->key.dst_net_bit_len,
                           rule->key.dst_port_range.start_port, rule->key.dst_port_range.end_port
#if 0
                           ,
                           rule->bool_accept_tcp ? '+' : '-', rule->bool_accept_udp ? '+' : '-', rule->bool_accept_icmp ? '+' : '-'
#endif
                           );
    if(rule->key.bool_tcp_configured) {
        print_start += sprintf(print_start, ",TCP%c", rule->bool_accept_tcp ? '+' : '-');
    }

    if(rule->key.bool_udp_configured) {
        print_start += sprintf(print_start, ",UDP%c", rule->bool_accept_udp ? '+' : '-');
    }

    if(rule->key.bool_icmp_configured) {
        print_start += sprintf(print_start, ",ICMP%c", rule->bool_accept_icmp ? '+' : '-');
    }

    return buf;
}



/* for [-Wmissing-declarations] */
uint8_t march_cidr_and_address (in_addr_t network, uint8_t net_bitlen, in_addr_t ip_addr);

uint8_t march_cidr_and_address (in_addr_t network, uint8_t net_bitlen, in_addr_t ip_addr) {

    in_addr_t mask = 0, ip_addr_network = 0;

    network = ntohl(network);
    ip_addr = ntohl(ip_addr);
    uint32_t mask1 = net_bitlen != 0 ? ((~mask) << (32u-net_bitlen)) : 0;
    ip_addr_network = ip_addr & mask1;
    if(network == ip_addr_network) {
        return net_bitlen + 1; // march 0.0.0.0/0 still march success, that case return 1
    } else {
        return 0;
    }
}

/* for [-Wmissing-declarations] */
uint8_t march_rule_and_cache_key (filter_rule_key_t *rule_key, packet_address_proto_info_t *pkt_addr_info);

// if ports march, compare cidr. if cidr ok, return sum of src&dst cidr net_bitlen. means always select larger net_bitlen record when multi record is marched.
uint8_t march_rule_and_cache_key (filter_rule_key_t *rule_key, packet_address_proto_info_t *pkt_addr_info) {

    // march failed if proto is not configured at the rule.
    switch(pkt_addr_info->proto) {
        case FPP_ICMP:
            if(!rule_key->bool_icmp_configured) {
                return 0;
            }
            break;
        case FPP_UDP:
            if(!rule_key->bool_udp_configured) {
                return 0;
            }
            break;
        case FPP_TCP:
            if(!rule_key->bool_tcp_configured) {
                return 0;
            }
            break;
        default:
            return 0;
    }

    // ignore ports for ICMP proto.
    if(pkt_addr_info->proto == FPP_ICMP || (rule_key->src_port_range.start_port <= pkt_addr_info->src_port
                                            && pkt_addr_info->src_port <= rule_key->src_port_range.end_port
                                            && rule_key->dst_port_range.start_port <= pkt_addr_info->dst_port
                                            && pkt_addr_info->dst_port <= rule_key->dst_port_range.end_port)) {
        uint8_t march_src_score = march_cidr_and_address(rule_key->src_net_cidr, rule_key->src_net_bit_len, pkt_addr_info->src_ip);
        uint8_t march_dst_score = march_cidr_and_address(rule_key->dst_net_cidr, rule_key->dst_net_bit_len, pkt_addr_info->dst_ip);
        if((march_src_score > 0) && (march_dst_score > 0)) {
            return march_src_score + march_dst_score;
        }
    }

    return(0);
}

/* for [-Wmissing-declarations] */
filter_rule_t* get_filter_rule (filter_rule_t **rules, packet_address_proto_info_t *pkt_addr_info);

filter_rule_t* get_filter_rule (filter_rule_t **rules, packet_address_proto_info_t *pkt_addr_info) {

    filter_rule_t *item = 0, *tmp = 0, *marched_rule = 0;
    int march_score = 0;

    HASH_ITER(hh, *rules, item, tmp) {
        /* ... it is safe to delete and free s here */
        uint8_t cur_march_score = march_rule_and_cache_key(&(item->key), pkt_addr_info);
        if(cur_march_score > march_score) {
            marched_rule = item;
            march_score = cur_march_score;
        }
    }

    return marched_rule;
}


/* for [-Wmissing-declarations] */
void update_and_clear_cache_if_need (network_traffic_filter_t *filter);

void update_and_clear_cache_if_need (network_traffic_filter_t *filter) {

    if(++(filter->work_count_scene_last_clear) > CLEAR_CACHE_EVERY_X_COUNT) {
        filter_rule_pair_cache_t *item = NULL, *tmp = NULL;
        HASH_ITER(hh, filter->connections_rule_cache, item, tmp) {
            /* ... it is safe to delete and free s here */
            if(item->active_count < CLAER_CACHE_ACTIVE_COUNT) {
                traceEvent(TRACE_DEBUG, "### DELETE filter cache %s", get_filter_packet_info_log_string(&item->key));
                HASH_DEL(filter->connections_rule_cache, item);
                free(item);
            } else {
                item->active_count = 0;
            }
        }
        filter->work_count_scene_last_clear = 0;
    }
}

/* for [-Wmissing-declarations] */
filter_rule_pair_cache_t* get_or_create_filter_rule_cache (network_traffic_filter_t *filter, packet_address_proto_info_t *pkt_addr_info);

filter_rule_pair_cache_t* get_or_create_filter_rule_cache (network_traffic_filter_t *filter, packet_address_proto_info_t *pkt_addr_info) {

    filter_rule_pair_cache_t* rule_cache_find_result = 0;
    HASH_FIND(hh, filter->connections_rule_cache, pkt_addr_info, sizeof(packet_address_proto_info_t), rule_cache_find_result);
    if(!rule_cache_find_result) {
        filter_rule_t* rule = get_filter_rule(&filter->rules, pkt_addr_info);
        if(!rule) {
            return NULL;
        }

        rule_cache_find_result = malloc(sizeof(filter_rule_pair_cache_t));
        memset(rule_cache_find_result, 0, sizeof(filter_rule_pair_cache_t));
        rule_cache_find_result->key = *pkt_addr_info;
        switch(rule_cache_find_result->key.proto) {
            case FPP_ICMP:
                rule_cache_find_result->bool_allow_traffic = rule->bool_accept_icmp;
                break;
            case FPP_UDP:
                rule_cache_find_result->bool_allow_traffic = rule->bool_accept_udp;
                break;
            case FPP_TCP:
                rule_cache_find_result->bool_allow_traffic = rule->bool_accept_tcp;
                break;
            default:
                traceEvent(TRACE_WARNING, "### Generate filter rule cache failed!");
                return NULL;
        }
        traceEvent(TRACE_DEBUG, "### ADD filter cache %s", get_filter_packet_info_log_string(&rule_cache_find_result->key));
        HASH_ADD(hh, filter->connections_rule_cache, key, sizeof(packet_address_proto_info_t), rule_cache_find_result);
    }
    ++(rule_cache_find_result->active_count);
    update_and_clear_cache_if_need(filter);

    return rule_cache_find_result;
}

/* for [-Wmissing-declarations] */
n2n_verdict filter_packet_from_peer (network_traffic_filter_t *filter, n2n_edge_t *eee, const n2n_sock_t *peer, uint8_t *payload, uint16_t payload_size);

n2n_verdict filter_packet_from_peer (network_traffic_filter_t *filter, n2n_edge_t *eee, const n2n_sock_t *peer, uint8_t *payload, uint16_t payload_size) {

    filter_rule_pair_cache_t *cur_pkt_rule = 0;
    packet_address_proto_info_t pkt_info;

    collect_packet_info(&pkt_info, payload, payload_size);
    cur_pkt_rule = get_or_create_filter_rule_cache(filter, &pkt_info);
    if(cur_pkt_rule && !cur_pkt_rule->bool_allow_traffic) {
        traceEvent(TRACE_DEBUG, "### DROP %s", get_filter_packet_info_log_string(&pkt_info));
        return N2N_DROP;
    }

    return N2N_ACCEPT;
}

/* for [-Wmissing-declarations] */
n2n_verdict filter_packet_from_tap (network_traffic_filter_t *filter, n2n_edge_t *eee, uint8_t *payload, uint16_t payload_size);

n2n_verdict filter_packet_from_tap (network_traffic_filter_t *filter, n2n_edge_t *eee, uint8_t *payload, uint16_t payload_size) {

    filter_rule_pair_cache_t *cur_pkt_rule = 0;
    packet_address_proto_info_t pkt_info;

    collect_packet_info(&pkt_info, payload, payload_size);
    cur_pkt_rule = get_or_create_filter_rule_cache(filter, &pkt_info);
    if(cur_pkt_rule && !cur_pkt_rule->bool_allow_traffic) {
        traceEvent(TRACE_DEBUG, "### DROP %s", get_filter_packet_info_log_string(&pkt_info));
        return N2N_DROP;
    }

    return N2N_ACCEPT;
}

/* for [-Wmissing-declarations] */
network_traffic_filter_t *create_network_traffic_filter ();

network_traffic_filter_t *create_network_traffic_filter () {

    network_traffic_filter_t *filter = malloc(sizeof(network_traffic_filter_t));

    memset(filter, 0, sizeof(network_traffic_filter_t));
    filter->filter_packet_from_peer = filter_packet_from_peer;
    filter->filter_packet_from_tap = filter_packet_from_tap;

    return filter;
}

/* for [-Wmissing-declarations] */
void destroy_network_traffic_filter (network_traffic_filter_t *filter);

void destroy_network_traffic_filter (network_traffic_filter_t *filter) {

    filter_rule_t *el = 0, *tmp = 0;
    filter_rule_pair_cache_t* el1 = 0, * tmp1 = 0;

    HASH_ITER(hh, filter->rules, el, tmp) {
        HASH_DEL(filter->rules, el);
        free(el);
    }

    HASH_ITER(hh, filter->connections_rule_cache, el1, tmp1) {
        HASH_DEL(filter->connections_rule_cache, el1);
        free(el);
    }

    free(filter);
}

/* for [-Wmissing-declarations] */
void network_traffic_filter_add_rule (network_traffic_filter_t* filter, filter_rule_t* rules);

void network_traffic_filter_add_rule (network_traffic_filter_t* filter, filter_rule_t* rules) {

    filter_rule_t *item = NULL, *tmp = NULL;

    HASH_ITER(hh, rules, item, tmp) {
        filter_rule_t *new_rule = malloc(sizeof(filter_rule_t));
        memcpy(new_rule, item, sizeof(filter_rule_t));
        HASH_ADD(hh, filter->rules, key, sizeof(filter_rule_key_t), new_rule);
        traceEvent(TRACE_NORMAL, "### ADD network traffic filter %s", get_filter_rule_info_log_string(new_rule));
    }
}

/* for [-Wmissing-declarations] */
in_addr_t get_int32_addr_from_ip_string (const char* begin, const char* next_pos_of_last_char);

in_addr_t get_int32_addr_from_ip_string (const char* begin, const char* next_pos_of_last_char) {

    char buf[16] = {0};

    if((next_pos_of_last_char - begin) > 15) {
        traceEvent(TRACE_WARNING, "Internal Error");
        return -1;
    }
    memcpy(buf, begin, (next_pos_of_last_char - begin));

    return inet_addr(buf);
}

/* for [-Wmissing-declarations] */
int get_int32_from_number_string (const char* begin, const char* next_pos_of_last_char);

int get_int32_from_number_string (const char* begin, const char* next_pos_of_last_char) {

    char buf[6] = {0};

    if((next_pos_of_last_char - begin) > 5 ) { // max is 65535, 5 char
        traceEvent(TRACE_WARNING, "Internal Error");
        return 0;
    }
    memcpy(buf, begin, (next_pos_of_last_char - begin));

    return atoi(buf);
}

/* for [-Wmissing-declarations] */
void process_traffic_filter_proto (const char* begin, const char* next_pos_of_last_char, filter_rule_t *rule_struct);

void process_traffic_filter_proto (const char* begin, const char* next_pos_of_last_char, filter_rule_t *rule_struct) {

    char buf[6] = {0};

    if((next_pos_of_last_char - begin) > 5 ) { // max length str is "ICMP+", 5 char
        traceEvent(TRACE_WARNING, "Internal Error");
    }
    memcpy(buf, begin, (next_pos_of_last_char - begin));

    if(strstr(buf, "TCP")) {
        rule_struct->key.bool_tcp_configured = 1;
        rule_struct->bool_accept_tcp = buf[3] == '+';
    } else if(strstr(buf, "UDP")) {
        rule_struct->key.bool_udp_configured = 1;
        rule_struct->bool_accept_udp = buf[3] == '+';
    } else if(strstr(buf, "ICMP")) {
        rule_struct->key.bool_icmp_configured = 1;
        rule_struct->bool_accept_icmp = buf[4] == '+';
    } else {
        traceEvent(TRACE_WARNING, "Invalid Proto : %s", buf);
    }
}

typedef enum {
    FPS_SRC_NET = 1,
    FPS_SRC_NET_BIT_LEN,
    FPS_SRC_PORT_SINGLE,
    FPS_SRC_PORT_RANGE,
    FPS_SRC_PORT_START,
    FPS_SRC_PORT_END,
    FPS_DST_NET,
    FPS_DST_NET_BIT_LEN,
    FPS_DST_PORT_SINGLE,
    FPS_DST_PORT_RANGE,
    FPS_DST_PORT_START,
    FPS_DST_PORT_END,
    FPS_PROTO
} filter_process_stage;

/* for [-Wmissing-declarations] */
uint8_t process_traffic_filter_rule_str (const char *rule_str, filter_rule_t *rule_struct);

uint8_t process_traffic_filter_rule_str (const char *rule_str, filter_rule_t *rule_struct) {

    const char *cur_pos = rule_str, *stage_begin_pos = rule_str;
    filter_process_stage stage = FPS_SRC_NET;

    while(1) {
        switch(stage) {
            case FPS_SRC_NET: {
                if((*cur_pos >= '0' && *cur_pos <= '9') || *cur_pos == '.') {
                    ; // Normal FPS_SRC_NET, next char
                } else if(*cur_pos == '/') {
                    // FPS_SRC_NET finish, next is FPS_SRC_NET_BIT_LEN
                    rule_struct->key.src_net_cidr = get_int32_addr_from_ip_string(stage_begin_pos, cur_pos);
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_SRC_NET_BIT_LEN;
                } else if(*cur_pos == ':') {
                    // FPS_SRC_NET finish, ignore FPS_SRC_NET_BIT_LEN(default 32), next is one of FPS_SRC_PORT_RANGE/FPS_SRC_PORT_SINGLE
                    rule_struct->key.src_net_cidr = get_int32_addr_from_ip_string(stage_begin_pos, cur_pos);
                    rule_struct->key.src_net_bit_len = 32;
                    stage_begin_pos = cur_pos + 1;
                    if(*(cur_pos + 1) == '[') {
                        stage = FPS_SRC_PORT_RANGE;
                    } else {
                        stage = FPS_SRC_PORT_SINGLE;
                    }
                } else if(*cur_pos == ',') {
                    // FPS_SRC_NET finish, ignore FPS_SRC_NET_BIT_LEN(default 32), ignore FPS_SRC_PORT(default all),
                    // next is FPS_DST_NET
                    rule_struct->key.src_net_cidr = get_int32_addr_from_ip_string(stage_begin_pos, cur_pos);
                    rule_struct->key.src_net_bit_len = 32;
                    rule_struct->key.src_port_range.start_port = 0;
                    rule_struct->key.src_port_range.end_port = 65535;
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_DST_NET;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_SRC_NET_BIT_LEN: {
                if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                    ; // Normal FPS_SRC_NET_BIT_LEN, next char
                } else if(*cur_pos == ':') {
                    // FPS_SRC_NET_BIT_LEN finish, next is one of FPS_SRC_PORT_RANGE/FPS_SRC_PORT_SINGLE
                    rule_struct->key.src_net_bit_len = get_int32_from_number_string(stage_begin_pos, cur_pos);
                    stage_begin_pos = cur_pos + 1;
                    if(*(cur_pos + 1) == '[') {
                        stage = FPS_SRC_PORT_RANGE;
                    } else {
                        stage = FPS_SRC_PORT_SINGLE;
                    }
                } else if(*cur_pos == ',') {
                    // FPS_SRC_NET_BIT_LEN finish, ignore FPS_SRC_PORT(default all), next is FPS_DST_NET
                    rule_struct->key.src_net_bit_len = get_int32_from_number_string(stage_begin_pos, cur_pos);;
                    rule_struct->key.src_port_range.start_port = 0;
                    rule_struct->key.src_port_range.end_port = 65535;
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_DST_NET;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_SRC_PORT_SINGLE: {
                if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                    ; // Normal FPS_SRC_PORT_SINGLE, next char
                } else if(*cur_pos == ',') {
                    // FPS_SRC_PORT_SINGLE finish, next is FPS_DST_NET
                    rule_struct->key.src_port_range.start_port = get_int32_from_number_string(stage_begin_pos, cur_pos);
                    rule_struct->key.src_port_range.end_port = rule_struct->key.src_port_range.start_port;
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_DST_NET;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_SRC_PORT_RANGE: {
                if(*cur_pos == '[') {
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_SRC_PORT_START;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_SRC_PORT_START: {
                if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                    ; // Normal FPS_SRC_PORT_START, next char
                } else if(*cur_pos == ',') {
                    // FPS_SRC_PORT_START finish, next is FPS_SRC_PORT_END
                    rule_struct->key.src_port_range.start_port = get_int32_from_number_string(stage_begin_pos, cur_pos);
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_SRC_PORT_END;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_SRC_PORT_END: {
                if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                    ; // Normal FPS_SRC_PORT_END, next char
                } else if((*cur_pos == ']') && (*(cur_pos + 1) == ',')) {
                    // FPS_SRC_PORT_END finish, next is FPS_DST_NET
                    rule_struct->key.src_port_range.end_port = get_int32_from_number_string(stage_begin_pos, cur_pos);
                    stage_begin_pos = cur_pos + 2;
                    stage = FPS_DST_NET;
                    ++cur_pos; //skip next char ','
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_DST_NET: {
                if((*cur_pos >= '0' && *cur_pos <= '9') || *cur_pos == '.') {
                    ; // Normal FPS_DST_NET, next char
                } else if(*cur_pos == '/') {
                    // FPS_DST_NET finish, next is FPS_DST_NET_BIT_LEN
                    rule_struct->key.dst_net_cidr = get_int32_addr_from_ip_string(stage_begin_pos, cur_pos);
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_DST_NET_BIT_LEN;
                } else if(*cur_pos == ':') {
                    // FPS_DST_NET finish, ignore FPS_DST_NET_BIT_LEN(default 32), next is one of FPS_DST_PORT_RANGE/FPS_DST_PORT_SINGLE
                    rule_struct->key.dst_net_cidr = get_int32_addr_from_ip_string(stage_begin_pos, cur_pos);
                    rule_struct->key.dst_net_bit_len = 32;
                    stage_begin_pos = cur_pos + 1;
                    if(*(cur_pos + 1) == '[') {
                        stage = FPS_DST_PORT_RANGE;
                    } else {
                        stage = FPS_DST_PORT_SINGLE;
                    }
                } else if((*cur_pos == ',') || (*cur_pos == 0)) {
                    // FPS_DST_NET finish, ignore FPS_DST_NET_BIT_LEN(default 32), ignore FPS_DST_PORT(default all),
                    // next is FPS_PROTO
                    rule_struct->key.dst_net_cidr = get_int32_addr_from_ip_string(stage_begin_pos, cur_pos);
                    rule_struct->key.dst_net_bit_len = 32;
                    rule_struct->key.dst_port_range.start_port = 0;
                    rule_struct->key.dst_port_range.end_port = 65535;
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_PROTO;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_DST_NET_BIT_LEN: {
                if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                    ; // Normal FPS_DST_NET_BIT_LEN, next char
                } else if(*cur_pos == ':') {
                    // FPS_DST_NET_BIT_LEN finish, next is one of FPS_DST_PORT_RANGE/FPS_DST_PORT_SINGLE
                    rule_struct->key.dst_net_bit_len = get_int32_from_number_string(stage_begin_pos, cur_pos);
                    stage_begin_pos = cur_pos + 1;
                    if(*(cur_pos + 1) == '[') {
                        stage = FPS_DST_PORT_RANGE;
                    } else {
                        stage = FPS_DST_PORT_SINGLE;
                    }
                } else if((*cur_pos == ',') || (*cur_pos == 0)) {
                    // FPS_DST_NET_BIT_LEN finish, ignore FPS_DST_PORT(default all), next is FPS_PROTO
                    rule_struct->key.dst_net_bit_len = get_int32_from_number_string(stage_begin_pos, cur_pos);;
                    rule_struct->key.dst_port_range.start_port = 0;
                    rule_struct->key.dst_port_range.end_port = 65535;
                    stage_begin_pos = cur_pos + 1;
                    stage = FPS_PROTO;
                } else {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
                break;
            }

            case FPS_DST_PORT_SINGLE: {
            if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                ; // Normal FPS_DST_PORT_SINGLE, next char
            } else if((*cur_pos == ',') || (*cur_pos == 0)) {
                // FPS_DST_PORT_SINGLE finish, next is FPS_PROTO
                rule_struct->key.dst_port_range.start_port = get_int32_from_number_string(stage_begin_pos, cur_pos);
                rule_struct->key.dst_port_range.end_port = rule_struct->key.dst_port_range.start_port;
                stage_begin_pos = cur_pos + 1;
                stage = FPS_PROTO;
            } else {
                traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                return 0;
            }
            break;
        }

        case FPS_DST_PORT_RANGE: {
            if(*cur_pos == '[') {
                stage_begin_pos = cur_pos + 1;
                stage = FPS_DST_PORT_START;
            } else {
                traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                return 0;
            }
            break;
        }

        case FPS_DST_PORT_START: {
            if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                ; // Normal FPS_DST_PORT_START, next char
            } else if(*cur_pos == ',') {
                // FPS_DST_PORT_START finish, next is FPS_DST_PORT_END
                rule_struct->key.dst_port_range.start_port = get_int32_from_number_string(stage_begin_pos, cur_pos);
                stage_begin_pos = cur_pos + 1;
                stage = FPS_DST_PORT_END;
            } else {
                traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                return 0;
            }
            break;
        }

        case FPS_DST_PORT_END: {
            if((*cur_pos >= '0') && (*cur_pos <= '9')) {
                ; // Normal FPS_DST_PORT_END, next char
            } else if(*cur_pos == ']') {
                // FPS_DST_PORT_END finish, next is FPS_PROTO
                rule_struct->key.dst_port_range.end_port = get_int32_from_number_string(stage_begin_pos, cur_pos);
                stage = FPS_PROTO;
                if(*(cur_pos + 1) == ',') {
                    stage_begin_pos = cur_pos + 2;
                    ++cur_pos; //skip next char ','
                } else if(*(cur_pos + 1) != 0) {
                    traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                    return 0;
                }
            } else {
                traceEvent(TRACE_WARNING, "process filter rule with error char %c at pos %d", *cur_pos, cur_pos - rule_str);
                return 0;
            }
            break;
        }

        case FPS_PROTO: {
            if((*cur_pos != '-') && (*cur_pos != '+') && (*cur_pos != ',')) {
                ; // Normal FPS_PROTO. next char
            } else if(*cur_pos != ',') {
                process_traffic_filter_proto(stage_begin_pos, cur_pos + 1, rule_struct);
                if(*(cur_pos+1) == 0) { // end of whole rule string
                    break;
                } else { // new proto info, and skip next char ','
                    stage_begin_pos = cur_pos + 2;
                    ++cur_pos;
                }
            } else {
                traceEvent(TRACE_WARNING, "Internal Error: ',' should skiped", *cur_pos, cur_pos - rule_str);
                return 0;
            }
            break;
        }
    }

    if(0 == *cur_pos) {
        break;
    }
    ++cur_pos;
    }

    return 1;
}
