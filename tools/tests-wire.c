/*
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 */

#include <inttypes.h>

#include "n2n.h"
#include "hexdump.h"

void init_ip_subnet (n2n_ip_subnet_t * d) {
    d->net_addr = 0x20212223;
    d->net_bitlen = 25;
}

void print_ip_subnet (char *test_name, char *field, n2n_ip_subnet_t * d) {
    printf("%s: %s.net_addr = 0x%08x\n",
           test_name, field, d->net_addr);
    printf("%s: %s.net_bitlen = %i\n",
           test_name, field, d->net_bitlen);
}

void init_mac (n2n_mac_t mac, const uint8_t o0, const uint8_t o1,
               const uint8_t o2, const uint8_t o3,
               const uint8_t o4, const uint8_t o5) {
    mac[0] = o0;
    mac[1] = o1;
    mac[2] = o2;
    mac[3] = o3;
    mac[4] = o4;
    mac[5] = o5;
}

void print_mac (char *test_name, char *field, n2n_mac_t mac) {
    printf("%s: %s[] = %x:%x:%x:%x:%x:%x\n",
           test_name, field,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void init_auth (n2n_auth_t *auth) {
    auth->scheme = n2n_auth_simple_id;
    auth->token_size = 16;
    auth->token[0] = 0xfe;
    auth->token[4] = 0xfd;
    auth->token[8] = 0xfc;
    auth->token[15] = 0xfb;
}

void print_auth (char *test_name, char *field, n2n_auth_t *auth) {
    printf("%s: %s.scheme = %i\n", test_name, field, auth->scheme);
    printf("%s: %s.token_size = %i\n", test_name, field, auth->token_size);
    printf("%s: %s.token[0] = 0x%02x\n", test_name, field, auth->token[0]);
}

void init_common (n2n_common_t *common, char *community) {
    memset( common, 0, sizeof(*common) );
    common->ttl = N2N_DEFAULT_TTL;
    common->flags = 0;
    strncpy( (char *)common->community, community, N2N_COMMUNITY_SIZE);
    common->community[N2N_COMMUNITY_SIZE - 1] = '\0';
}

void print_common (char *test_name, n2n_common_t *common) {
    printf("%s: common.ttl = %i\n", test_name, common->ttl);
    printf("%s: common.flags = %i\n", test_name, common->flags);
    printf("%s: common.community = \"%s\"\n", test_name, common->community);
}

void test_REGISTER (n2n_common_t *common) {
    char *test_name = "REGISTER";

    common->pc = n2n_register;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_REGISTER_t reg;
    memset( &reg, 0, sizeof(reg) );
    init_mac( reg.srcMac, 0,1,2,3,4,5);
    init_mac( reg.dstMac, 0x10,0x11,0x12,0x13,0x14,0x15);
    init_ip_subnet(&reg.dev_addr);
    strcpy( (char *)reg.dev_desc, "Dummy_Dev_Desc" );

    printf("%s: reg.cookie = %i\n", test_name, reg.cookie);
    print_mac(test_name, "reg.srcMac", reg.srcMac);
    print_mac(test_name, "reg.dstMac", reg.dstMac);
    // TODO: print reg.sock
    print_ip_subnet(test_name, "reg.dev_addr", &reg.dev_addr);
    printf("%s: reg.dev_desc = \"%s\"\n", test_name, reg.dev_desc);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_REGISTER( pktbuf, &idx, common, &reg);

    printf("%s: output retval = 0x%" PRIx64 "\n", test_name, retval);
    printf("%s: output idx = 0x%" PRIx64 "\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_REGISTER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_REGISTER_SUPER (n2n_common_t *common) {
    char *test_name = "REGISTER_SUPER";

    common->pc = n2n_register_super;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_REGISTER_SUPER_t reg;
    memset( &reg, 0, sizeof(reg) );
    init_mac( reg.edgeMac, 0x20,0x21,0x22,0x23,0x24,0x25);
    // n2n_sock_t sock
    init_ip_subnet(&reg.dev_addr);
    strcpy( (char *)reg.dev_desc, "Dummy_Dev_Desc" );
    init_auth(&reg.auth);
    reg.key_time = 600;


    printf("%s: reg.cookie = %i\n", test_name, reg.cookie);
    print_mac(test_name, "reg.edgeMac", reg.edgeMac);
    // TODO: print reg.sock
    print_ip_subnet(test_name, "reg.dev_addr", &reg.dev_addr);
    printf("%s: reg.dev_desc = \"%s\"\n", test_name, reg.dev_desc);
    print_auth(test_name, "reg.auth", &reg.auth);
    printf("%s: reg.key_time = %" PRIi32 "\n", test_name, reg.key_time);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_REGISTER_SUPER( pktbuf, &idx, common, &reg);

    printf("%s: output retval = 0x%" PRIx64 "\n", test_name, retval);
    printf("%s: output idx = 0x%" PRIx64 "\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_REGISTER_SUPER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

void test_UNREGISTER_SUPER (n2n_common_t *common) {
    char *test_name = "UNREGISTER_SUPER";

    common->pc = n2n_unregister_super;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_UNREGISTER_SUPER_t unreg;
    memset( &unreg, 0, sizeof(unreg) );
    init_auth(&unreg.auth);
    init_mac( unreg.srcMac, 0x30,0x31,0x32,0x33,0x34,0x35);


    print_auth(test_name, "unreg.auth", &unreg.auth);
    print_mac(test_name, "unreg.srcMac", unreg.srcMac);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_UNREGISTER_SUPER( pktbuf, &idx, common, &unreg);

    printf("%s: output retval = 0x%" PRIx64 "\n", test_name, retval);
    printf("%s: output idx = 0x%" PRIx64 "\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_UNREGISTER_SUPER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

int main (int argc, char * argv[]) {
    char *test_name = "environment";

    n2n_common_t common;
    init_common( &common, "abc123def456z" );
    print_common( test_name, &common );
    printf("\n");

    test_REGISTER(&common);
    test_REGISTER_SUPER(&common);
    test_UNREGISTER_SUPER(&common);
    // TODO: add more wire tests

    return 0;
}

