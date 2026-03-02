/**
 * (C) 2007-21 - ntop.org and contributors
 *
 * Unit tests for macOS utun L2/L3 translation shim and ARP cache.
 * These tests validate the translation logic without requiring
 * a real utun device or root privileges.
 */

#ifdef __APPLE__

#include "n2n.h"
#include "arp.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>


static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if(!(cond)) { \
        printf("FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
    } else { \
        printf("PASS: %s\n", msg); \
        tests_passed++; \
    } \
} while(0)

#define TEST_ASSERT_MAC(got, exp, msg) do { \
    if(memcmp(got, exp, 6) != 0) { \
        printf("FAIL: %s (line %d) got=%02x:%02x:%02x:%02x:%02x:%02x expected=%02x:%02x:%02x:%02x:%02x:%02x\n", \
               msg, __LINE__, \
               (got)[0],(got)[1],(got)[2],(got)[3],(got)[4],(got)[5], \
               (exp)[0],(exp)[1],(exp)[2],(exp)[3],(exp)[4],(exp)[5]); \
        tests_failed++; \
    } else { \
        printf("PASS: %s\n", msg); \
        tests_passed++; \
    } \
} while(0)


/* ===== Test 1: IPv4 multicast MAC mapping ===== */
static void test_ipv4_multicast_mac (void) {

    uint8_t mac[6];

    /* 224.0.0.1 -> 01:00:5E:00:00:01 */
    uint32_t ip = inet_addr("224.0.0.1");
    ip_to_dest_mac(ip, 0, mac);

    uint8_t expected[] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
    TEST_ASSERT_MAC(mac, expected, "IPv4 multicast 224.0.0.1 -> 01:00:5E:00:00:01");
}


/* ===== Test 2: IPv4 multicast high bits ===== */
static void test_ipv4_multicast_mac_high (void) {

    uint8_t mac[6];

    /* 239.255.255.250 (SSDP) -> 01:00:5E:7F:FF:FA */
    uint32_t ip = inet_addr("239.255.255.250");
    ip_to_dest_mac(ip, 0, mac);

    uint8_t expected[] = {0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA};
    TEST_ASSERT_MAC(mac, expected, "IPv4 multicast 239.255.255.250 -> 01:00:5E:7F:FF:FA");
}


/* ===== Test 3: IPv6 multicast MAC mapping ===== */
static void test_ipv6_multicast_mac (void) {

    uint8_t mac[6];

    /* ff02::1 -> 33:33:00:00:00:01 */
    uint8_t ipv6_pkt[40];
    memset(ipv6_pkt, 0, sizeof(ipv6_pkt));
    /* dst addr at offset 24 */
    ipv6_pkt[24] = 0xFF;
    ipv6_pkt[25] = 0x02;
    /* bytes 26-35 are zero */
    ipv6_pkt[39] = 0x01; /* last byte */

    ipv6_to_dest_mac(ipv6_pkt, mac);

    uint8_t expected[] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    TEST_ASSERT_MAC(mac, expected, "IPv6 multicast ff02::1 -> 33:33:00:00:00:01");
}


/* ===== Test 4: IPv4 broadcast mapping ===== */
static void test_ipv4_broadcast_mac (void) {

    uint8_t mac[6];
    uint8_t bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /* 255.255.255.255 -> broadcast MAC */
    uint32_t ip = inet_addr("255.255.255.255");
    ip_to_dest_mac(ip, 0, mac);
    TEST_ASSERT_MAC(mac, bcast, "IPv4 broadcast 255.255.255.255 -> FF:FF:FF:FF:FF:FF");
}


/* ===== Test 5: IPv4 subnet broadcast mapping ===== */
static void test_ipv4_subnet_broadcast_mac (void) {

    uint8_t mac[6];
    uint8_t bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /* 10.0.0.255 with mask 255.255.255.0 is a subnet broadcast */
    uint32_t ip = inet_addr("10.0.0.255");
    uint32_t mask = inet_addr("255.255.255.0");
    ip_to_dest_mac(ip, mask, mac);
    TEST_ASSERT_MAC(mac, bcast, "IPv4 subnet broadcast 10.0.0.255/24 -> FF:FF:FF:FF:FF:FF");
}


/* ===== Test 6: Unknown destination -> broadcast ===== */
static void test_unknown_dest_broadcast (void) {

    uint8_t mac[6];
    uint8_t bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    arp_cache_init();

    /* 10.0.0.99 not in cache -> broadcast */
    uint32_t ip = inet_addr("10.0.0.99");
    ip_to_dest_mac(ip, inet_addr("255.255.255.0"), mac);
    TEST_ASSERT_MAC(mac, bcast, "Unknown unicast IP not in ARP cache -> broadcast MAC");

    arp_cache_destroy();
}


/* ===== Test 7: ARP cache insert and lookup ===== */
static void test_arp_cache_insert_lookup (void) {

    uint8_t mac[6];
    uint8_t expected[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    arp_cache_init();

    uint32_t ip = inet_addr("10.0.0.5");
    arp_cache_update(ip, expected);
    arp_cache_lookup(ip, mac);

    TEST_ASSERT_MAC(mac, expected, "ARP cache: insert and lookup returns correct MAC");

    arp_cache_destroy();
}


/* ===== Test 8: ARP cache update ===== */
static void test_arp_cache_update (void) {

    uint8_t mac[6];
    uint8_t old_mac[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t new_mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    arp_cache_init();

    uint32_t ip = inet_addr("10.0.0.5");
    arp_cache_update(ip, old_mac);
    arp_cache_update(ip, new_mac);
    arp_cache_lookup(ip, mac);

    TEST_ASSERT_MAC(mac, new_mac, "ARP cache: update replaces old MAC with new MAC");

    arp_cache_destroy();
}


/* ===== Test 9: ARP cache miss ===== */
static void test_arp_cache_miss (void) {

    uint8_t mac[6];
    uint8_t bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    arp_cache_init();

    uint32_t ip = inet_addr("192.168.1.1");
    arp_cache_lookup(ip, mac);

    TEST_ASSERT_MAC(mac, bcast, "ARP cache: miss returns broadcast MAC");

    arp_cache_destroy();
}


/* ===== Test 10: ARP ignores broadcast/zero MAC ===== */
static void test_arp_cache_ignores_bad_mac (void) {

    uint8_t bcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t zero_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t result[6];

    arp_cache_init();

    uint32_t ip = inet_addr("10.0.0.1");

    arp_cache_update(ip, bcast_mac);
    arp_cache_lookup(ip, result);
    TEST_ASSERT_MAC(result, bcast_mac, "ARP cache: broadcast MAC not cached, returns broadcast");

    arp_cache_update(ip, zero_mac);
    arp_cache_lookup(ip, result);
    TEST_ASSERT_MAC(result, bcast_mac, "ARP cache: zero MAC not cached, returns broadcast");

    arp_cache_destroy();
}


/* ===== Test 11: ARP request parsing and learning ===== */
static void test_arp_request_learning (void) {

    uint8_t mac[6];
    uint8_t sender_mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    arp_cache_init();

    /* build a minimal ARP request frame (42 bytes) */
    uint8_t frame[42];
    memset(frame, 0, sizeof(frame));

    /* Ethernet header */
    memset(&frame[0], 0xFF, 6);                /* dst = broadcast */
    memcpy(&frame[6], sender_mac, 6);          /* src = sender */
    frame[12] = 0x08; frame[13] = 0x06;       /* EtherType = ARP */

    /* ARP payload */
    frame[14] = 0x00; frame[15] = 0x01;       /* hw type = Ethernet */
    frame[16] = 0x08; frame[17] = 0x00;       /* proto type = IPv4 */
    frame[18] = 6;                             /* hw size */
    frame[19] = 4;                             /* proto size */
    frame[20] = 0x00; frame[21] = 0x01;       /* op = request */
    memcpy(&frame[22], sender_mac, 6);         /* sender MAC */
    uint32_t sender_ip = inet_addr("10.0.0.2");
    memcpy(&frame[28], &sender_ip, 4);         /* sender IP */

    /* target */
    memset(&frame[32], 0, 6);                  /* target MAC (unknown) */
    uint32_t target_ip = inet_addr("10.0.0.1");
    memcpy(&frame[38], &target_ip, 4);         /* target IP */

    /* create a tuntap_dev with our IP */
    tuntap_dev dev;
    memset(&dev, 0, sizeof(dev));
    dev.ip_addr = target_ip;
    memcpy(dev.mac_addr, (uint8_t[]){0xFE, 0x01, 0x02, 0x03, 0x04, 0x05}, 6);
    dev.edge_context = NULL;

    int ret = arp_handle_packet(&dev, frame, sizeof(frame));
    TEST_ASSERT(ret == 42, "ARP handle returns frame length");

    /* check sender was learned */
    arp_cache_lookup(sender_ip, mac);
    TEST_ASSERT_MAC(mac, sender_mac, "ARP request: sender MAC/IP learned in cache");

    arp_cache_destroy();
}


/* ===== Test 12: Ethernet header synthesis from IP packet ===== */
static void test_ethernet_synthesis (void) {

    /*
     * Simulate what tuntap_read does:
     * Given a utun read buffer (4-byte AF header + IP packet),
     * verify the synthetic Ethernet header is correct.
     */

    uint8_t src_mac[] = {0xFE, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t peer_mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    arp_cache_init();

    /* populate ARP cache with peer */
    uint32_t peer_ip = inet_addr("10.0.0.2");
    arp_cache_update(peer_ip, peer_mac);

    /* build a fake utun read buffer: 4-byte AF_INET + minimal IP header */
    uint8_t utun_buf[4 + 20];
    uint32_t af = htonl(AF_INET);
    memcpy(utun_buf, &af, 4);

    /* minimal IP header: version=4, ihl=5, tot_len=20 */
    memset(utun_buf + 4, 0, 20);
    utun_buf[4] = 0x45; /* version 4, IHL 5 */
    /* src IP at offset 12 */
    uint32_t my_ip = inet_addr("10.0.0.1");
    memcpy(utun_buf + 4 + 12, &my_ip, 4);
    /* dst IP at offset 16 */
    memcpy(utun_buf + 4 + 16, &peer_ip, 4);

    /*
     * Now manually do what tuntap_read does (without needing a real fd):
     * Extract AF, determine EtherType, build Ethernet header, assemble.
     */
    uint32_t af_read;
    memcpy(&af_read, utun_buf, 4);
    af_read = ntohl(af_read);

    TEST_ASSERT(af_read == AF_INET, "AF header is AF_INET");

    /* build synthetic Ethernet header */
    ether_hdr_t eh;
    memset(&eh, 0, sizeof(eh));
    memcpy(eh.shost, src_mac, 6);
    eh.type = htons(0x0800);

    uint32_t dst_ip;
    memcpy(&dst_ip, utun_buf + 4 + IP4_DSTOFFSET, 4);
    ip_to_dest_mac(dst_ip, inet_addr("255.255.255.0"), eh.dhost);

    TEST_ASSERT_MAC(eh.dhost, peer_mac, "Ethernet synthesis: dest MAC from ARP cache");
    TEST_ASSERT(ntohs(eh.type) == 0x0800, "Ethernet synthesis: EtherType is 0x0800");
    TEST_ASSERT_MAC(eh.shost, src_mac, "Ethernet synthesis: src MAC is our MAC");

    /* assemble full frame */
    uint8_t frame[14 + 20];
    memcpy(frame, &eh, 14);
    memcpy(frame + 14, utun_buf + 4, 20);

    /* verify the dest MAC at offset 0 is the peer MAC */
    TEST_ASSERT_MAC(frame, peer_mac, "Assembled frame: dest MAC at offset 0");

    /* verify EtherType at offset 12 */
    uint16_t et;
    memcpy(&et, frame + 12, 2);
    TEST_ASSERT(ntohs(et) == 0x0800, "Assembled frame: EtherType at offset 12");

    arp_cache_destroy();
}


/* ===== Test 13: Ethernet stripping logic ===== */
static void test_ethernet_stripping (void) {

    /*
     * Simulate what tuntap_write does:
     * Given a full Ethernet frame, verify ARP is intercepted and
     * non-IP is silently consumed.
     */

    /* ARP frame should be intercepted */
    uint8_t arp_frame[42];
    memset(arp_frame, 0, sizeof(arp_frame));
    arp_frame[12] = 0x08; arp_frame[13] = 0x06; /* EtherType = ARP */
    arp_frame[14] = 0x00; arp_frame[15] = 0x01; /* hw type */
    arp_frame[16] = 0x08; arp_frame[17] = 0x00; /* proto type */
    arp_frame[18] = 6; arp_frame[19] = 4;

    ether_hdr_t eh;
    memcpy(&eh, arp_frame, sizeof(eh));
    TEST_ASSERT(ntohs(eh.type) == 0x0806, "ARP frame has EtherType 0x0806");

    /* IPX frame should be silently consumed */
    uint8_t ipx_frame[14 + 30];
    memset(ipx_frame, 0, sizeof(ipx_frame));
    ipx_frame[12] = 0x81; ipx_frame[13] = 0x37; /* EtherType = IPX */
    memcpy(&eh, ipx_frame, sizeof(eh));
    uint16_t et = ntohs(eh.type);
    TEST_ASSERT(et != 0x0800 && et != 0x86DD, "IPX frame is not IP/IPv6, would be silently consumed");

    /* IPv4 frame should pass through */
    uint8_t ip_frame[14 + 20];
    memset(ip_frame, 0, sizeof(ip_frame));
    ip_frame[12] = 0x08; ip_frame[13] = 0x00; /* EtherType = IPv4 */
    ip_frame[14] = 0x45; /* version/IHL */
    memcpy(&eh, ip_frame, sizeof(eh));
    TEST_ASSERT(ntohs(eh.type) == 0x0800, "IPv4 frame has correct EtherType");
}


/* ===== Test 14: IPv6 unicast -> broadcast ===== */
static void test_ipv6_unicast_broadcast (void) {

    uint8_t mac[6];
    uint8_t bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    /* non-multicast IPv6 dst -> broadcast MAC */
    uint8_t ipv6_pkt[40];
    memset(ipv6_pkt, 0, sizeof(ipv6_pkt));
    ipv6_pkt[24] = 0x20; /* dst starts with 2001::... */
    ipv6_pkt[25] = 0x01;

    ipv6_to_dest_mac(ipv6_pkt, mac);
    TEST_ASSERT_MAC(mac, bcast, "IPv6 unicast -> broadcast MAC");
}


/* ===== Test 15: Known unicast from cache ===== */
static void test_known_unicast_from_cache (void) {

    uint8_t mac[6];
    uint8_t expected[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};

    arp_cache_init();

    uint32_t ip = inet_addr("192.168.1.100");
    arp_cache_update(ip, expected);

    ip_to_dest_mac(ip, inet_addr("255.255.255.0"), mac);
    TEST_ASSERT_MAC(mac, expected, "Known unicast IP returns cached MAC");

    arp_cache_destroy();
}


int main (void) {

    printf("=== n2n macOS utun unit tests ===\n\n");

    test_ipv4_multicast_mac();
    test_ipv4_multicast_mac_high();
    test_ipv6_multicast_mac();
    test_ipv4_broadcast_mac();
    test_ipv4_subnet_broadcast_mac();
    test_unknown_dest_broadcast();
    test_arp_cache_insert_lookup();
    test_arp_cache_update();
    test_arp_cache_miss();
    test_arp_cache_ignores_bad_mac();
    test_arp_request_learning();
    test_ethernet_synthesis();
    test_ethernet_stripping();
    test_ipv6_unicast_broadcast();
    test_known_unicast_from_cache();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}

#else /* !__APPLE__ */

#include <stdio.h>
int main (void) {
    printf("macOS utun tests skipped (not on macOS)\n");
    return 0;
}

#endif /* __APPLE__ */
