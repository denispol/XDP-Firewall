#pragma once

#include <common/all.h>

#include <xdp/utils/logging.h>

#include <xdp/utils/maps.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

struct rule_ctx
{
    int matched;
    int action;
    u64 block_time;

    int pkt_len;

    u64 ip_pps;
    u64 ip_bps;

    u64 flow_pps;
    u64 flow_bps;

#ifdef ENABLE_FILTER_LOGGING
    u64 now;
#endif

    // Layer-4 information is copied into scalars (instead of storing header pointers) which keeps verifier complexity low.
    u8 protocol;

    // The layer-4 protocol whose header was parsed (0 if there is no layer-4 header such as with non-first fragments).
    u8 l4_proto;

    // Ports in network byte order.
    u16 src_port;
    u16 dst_port;

    // TCP flags byte (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN from most to least significant bit).
    u8 tcp_flags;

    u8 icmp_type;
    u8 icmp_code;

    struct iphdr* iph;
    struct ipv6hdr* iph6;
} typedef rule_ctx_t;

#ifdef ENABLE_FILTERS
static __always_inline long process_rule(u32 idx, void* data);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "rule.c"