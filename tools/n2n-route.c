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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include "n2n.h"


#define MGMT_PORT     5644
#define BUFFER_SIZE   2048
#define WITH_SOCKET      1
#define CORRECT_TAG      2


SOCKET connect_to_management_port (void) {

    SOCKET ret;
    struct sockaddr_in sock_addr;

    ret = socket (PF_INET, SOCK_DGRAM, 0);
    if((int)ret < 0)
        return -1;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock_addr.sin_port = htons(MGMT_PORT);
    if(0 != connect(ret, (struct sockaddr *)&sock_addr, sizeof(sock_addr)))
        return -1;

    return ret;
}


int get_addr_from_json (struct in_addr *addr, json_object_t *json, int tag_1, int tag_2, int flags) {

    int i;
    char *colon = NULL;

    if(NULL == json)
        return 0;

    for(i = 0; i < json->count; i++) {
        if(json->pairs[i].type == JSON_STRING) {
            if(!strcmp(json->pairs[i].key, &"sockaddr")) {
                // cut off port from IP address
                if((colon = strchr(json->pairs[i].value->string_value, ':'))) {
                    *colon = '\0';
                }
                if(inet_aton(json->pairs[i].value->string_value, addr)) {
                    flags |= WITH_SOCKET;
                }
            }
            if(!strcmp(json->pairs[i].key, &"_tag" )) {
                if((atoi(json->pairs[i].value->string_value) == tag_1)
                || (atoi(json->pairs[i].value->string_value) == tag_2)) {
                    flags |= CORRECT_TAG;
                }
            }
        } else if(json->pairs[i].type == JSON_OBJECT) {
            flags |= get_addr_from_json(addr, json, tag_1, tag_2, flags);
        }
    }

    return flags;
}


int main (int argc, char* argv[]) {

    SOCKET sock;
    size_t msg_len;
    char udp_buf[BUFFER_SIZE];
    fd_set socket_mask;
    struct timeval wait_time;
    json_object_t *json;
    int ret;
    int tag_read, tag_subscribe;
    struct in_addr *addr = malloc(sizeof(struct in_addr));

    n2n_srand(n2n_seed());

    sock = connect_to_management_port();
    if(sock == -1)
        goto end_route_tool;

    // send subscribe request to management port
    tag_subscribe = (uint32_t)(n2n_rand()) >> 1;
    msg_len = 0;
    msg_len += snprintf((char *) (udp_buf + msg_len), (BUFFER_SIZE - msg_len),
                        "s %u:1:n2n peer\n", tag_subscribe);
// !!! something smashes the edge when sending subscritpion request
//    ret = send(sock, udp_buf, msg_len, 0);

    // send read requests to management port
    tag_read = (uint32_t)(n2n_rand()) >> 1;
    msg_len = 0;
    msg_len += snprintf((char *) (udp_buf + msg_len), (BUFFER_SIZE - msg_len),
                        "r %u edges\n", tag_read);
    ret = send(sock, udp_buf, msg_len, 0);
    msg_len = 0;
    msg_len += snprintf((char *) (udp_buf + msg_len), (BUFFER_SIZE - msg_len),
                        "r %u supernodes\n", tag_read);
    ret = send(sock, udp_buf, msg_len, 0);

    // read answer packet by packet: udp_buf and msg_len get recycled from here on
    FD_ZERO(&socket_mask);
    FD_SET(sock, &socket_mask);
    wait_time.tv_sec = 1;
    wait_time.tv_usec = 0;

    while(1) {
        ret = select(sock + 1, &socket_mask, NULL, NULL, &wait_time);
        if(ret > 0) {
            if(FD_ISSET(sock, &socket_mask)) {
                msg_len = recv(sock, udp_buf, sizeof(udp_buf), 0);
                if((msg_len > 0) && (msg_len < sizeof(udp_buf))) {
                    // make sure it is a string
                    udp_buf[msg_len] = 0;
                    // handle the answer
                    json = json_parse(udp_buf);
                    ret = get_addr_from_json(addr, json, tag_read, tag_subscribe, 0);
                    json_free(json);
                    if(ret == (WITH_SOCKET | CORRECT_TAG)) {
                        // !!! handling, e.g. add address to hash list and envoy route command
                        printf("IP: %s\n", inet_ntoa(*addr));
                    } else if(ret != CORRECT_TAG) {
                        // unexpected tag stops reading
                        break;
                    }
                }
            } else
                // can this happen?
                break;
        } else {
            // error or time out (for now , only read once) !!!
            break;
        }
    }

    // send unsubscribe request to management port
    // !!!

end_route_tool:
    closesocket(sock);
    free(addr);

    return 0;
}
