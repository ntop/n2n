/*
 * (C) 2007-21 - ntop.org and contributors
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

#include "n2n.h"
#include "hexdump.h"

void test_REGISTER(n2n_common_t *common) {
    char *test_name = "REGISTER";

    common->pc = n2n_register;
    printf("%s: common.pc = %i\n", test_name, common->pc);

    n2n_REGISTER_t reg;
    memset( &reg, 0, sizeof(reg) );
    n2n_mac_t dummysrcMac={0,1,2,3,4,5};
    memcpy( reg.srcMac, dummysrcMac, sizeof(dummysrcMac));
    n2n_mac_t dummydstMac={0x10,0x11,0x12,0x13,0x14,0x15};
    memcpy( reg.dstMac, dummydstMac, sizeof(dummydstMac));
    reg.dev_addr.net_addr = 0x20212223;
    reg.dev_addr.net_bitlen = 25;
    strcpy( (char *)reg.dev_desc, "Dummy_Dev_Desc" );

    printf("%s: reg.cookie = %i\n", test_name, reg.cookie);
    // TODO: print reg.srcMac, reg.dstMac
    // TODO: print reg.sock
    printf("%s: reg.dev_addr.net_addr = 0x%08x\n", test_name, reg.dev_addr.net_addr);
    printf("%s: reg.dev_addr.net_bitlen = %i\n", test_name, reg.dev_addr.net_bitlen);
    printf("%s: reg.dev_desc = \"%s\"\n", test_name, reg.dev_desc);
    printf("\n");

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    size_t retval = encode_REGISTER( pktbuf, &idx, common, &reg);

    printf("%s: output retval = 0x%lx\n", test_name, retval);
    printf("%s: output idx = 0x%lx\n", test_name, idx);
    fhexdump(0, pktbuf, idx, stdout);

    // TODO: decode_REGISTER() and print

    fprintf(stderr, "%s: tested\n", test_name);
    printf("\n");
}

int main(int argc, char * argv[]) {
    char *test_name = "environment";

    n2n_community_t c;
    strncpy((char *)c, "abc123def456z", sizeof(c));

    n2n_common_t common;
    memset( &common, 0, sizeof(common) );
    common.ttl = N2N_DEFAULT_TTL;
    common.flags = 0;
    memcpy( common.community, c, N2N_COMMUNITY_SIZE );

    printf("%s: common.ttl = %i\n", test_name, common.ttl);
    printf("%s: common.flags = %i\n", test_name, common.flags);
    printf("%s: common.community = \"%s\"\n", test_name, common.community);
    printf("\n");

    test_REGISTER(&common);
    // TODO: add more wire tests

    return 0;
}

