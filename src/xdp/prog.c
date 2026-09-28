#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <common/all.h>

#include <xdp/utils/rl.h>
#include <xdp/utils/rule.h>
#include <xdp/utils/stats.h>
#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

struct 
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Retrieve stats map value.
    u32 key = 0;
    stats_t* stats = bpf_map_lookup_elem(&map_stats, &key);

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    // Check Ethernet protocol.
#ifdef ENABLE_IPV6
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
#else
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
#endif
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);
        
        return XDP_PASS;
    }

    // Initialize IP headers.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    u128 src_ip6 = 0;

    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IP))
    {
        iph = data + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }

        // An IHL below 5 is malformed and would make us parse layer-4 headers from inside of the IP header.
        if (unlikely(iph->ihl < 5))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
#ifdef ENABLE_IPV6
    else
    {
        iph6 = data + sizeof(struct ethhdr);

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }

        memcpy(&src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(src_ip6));
    }
#endif

    // Retrieve nanoseconds since system boot as timestamp.
    u64 now = bpf_ktime_get_ns();

    // Check block map.
    // This is done before any layer-4 processing so that blocked sources are dropped regardless of the protocol they use.
    u64 *blocked = NULL;

    if (iph)
    {
        blocked = bpf_map_lookup_elem(&map_block, &iph->saddr);
    }
#ifdef ENABLE_IPV6
    else
    {
        blocked = bpf_map_lookup_elem(&map_block6, &src_ip6);
    }
#endif
    
    if (blocked != NULL)
    {
        if (*blocked > 0 && now > *blocked)
        {
            // Remove element from map.
            if (iph)
            {
                bpf_map_delete_elem(&map_block, &iph->saddr);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_delete_elem(&map_block6, &src_ip6);
            }
#endif
        }
        else
        {
#ifdef DO_STATS_ON_BLOCK_MAP
            // Increase blocked stats entry.
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

            // They're still blocked. Drop the packet.
            return XDP_DROP;
        }
    }

#ifdef ENABLE_IP_RANGE_DROP
    if (iph && check_ip_range_drop(iph->saddr))
    {
#ifdef DO_STATS_ON_IP_RANGE_DROP_MAP
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

        return XDP_DROP;
    }
#endif

#ifdef ENABLE_FILTERS
    // Determine the layer-4 protocol and where its header starts.
    // The layer-4 header pointer is left as NULL for fragments that aren't the first fragment since they don't contain a layer-4 header.
    u8 protocol = 0;
    void *l4_hdr = NULL;

    if (iph)
    {
        protocol = iph->protocol;

        if (!(iph->frag_off & htons(IP_OFFSET)))
        {
            l4_hdr = (void *)iph + (iph->ihl * 4);
        }
    }
#ifdef ENABLE_IPV6
    else
    {
        protocol = iph6->nexthdr;
        void *hdr = (void *)(iph6 + 1);
        int non_first_frag = 0;

        // Walk IPv6 extension headers so they can't be used to bypass filters.
#pragma unroll
        for (int i = 0; i < IPV6_MAX_EXT_HDRS; i++)
        {
            if (protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_ROUTING || protocol == IPPROTO_DSTOPTS)
            {
                struct ipv6_opt_hdr *opt = hdr;

                if (unlikely(opt + 1 > (struct ipv6_opt_hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                protocol = opt->nexthdr;
                hdr += (opt->hdrlen + 1) * 8;
            }
            else if (protocol == IPPROTO_AH)
            {
                struct ipv6_opt_hdr *opt = hdr;

                if (unlikely(opt + 1 > (struct ipv6_opt_hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                protocol = opt->nexthdr;
                hdr += (opt->hdrlen + 2) * 4;
            }
            else if (protocol == IPPROTO_FRAGMENT)
            {
                struct ipv6_frag_hdr *frag = hdr;

                if (unlikely(frag + 1 > (struct ipv6_frag_hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                protocol = frag->nexthdr;
                hdr += sizeof(struct ipv6_frag_hdr);

                if (frag->frag_off & htons(IPV6_FRAG_OFFSET))
                {
                    non_first_frag = 1;

                    break;
                }
            }
            else
            {
                break;
            }
        }

        if (!non_first_frag)
        {
            l4_hdr = hdr;
        }
    }
#endif

    // We only want to process TCP, UDP, and ICMP protocols.
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP && ((iph && protocol != IPPROTO_ICMP) || (iph6 && protocol != IPPROTO_ICMPV6)))
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Retrieve total packet length.
    u16 pkt_len = data_end - data;

    // Parse layer-4 headers and copy the information filters need.
    u8 l4_proto = 0;

    u16 src_port = 0;
    u16 dst_port = 0;

    u8 tcp_flags = 0;

    u8 icmp_type = 0;
    u8 icmp_code = 0;

    if (l4_hdr)
    {
        switch (protocol)
        {
            case IPPROTO_TCP:
            {
                // Scan TCP header.
                struct tcphdr *tcph = l4_hdr;

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                l4_proto = IPPROTO_TCP;

                src_port = tcph->source;
                dst_port = tcph->dest;

                // The flags are stored in the 14th byte of the TCP header.
                tcp_flags = ((u8 *)tcph)[13];

                break;
            }

            case IPPROTO_UDP:
            {
                // Scan UDP header.
                struct udphdr *udph = l4_hdr;

                // Check UDP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                l4_proto = IPPROTO_UDP;

                src_port = udph->source;
                dst_port = udph->dest;

                break;
            }

            case IPPROTO_ICMP:
            {
                // Scan ICMP header.
                struct icmphdr *icmph = l4_hdr;

                // Check ICMP header.
                if (unlikely(icmph + 1 > (struct icmphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                l4_proto = IPPROTO_ICMP;

                icmp_type = icmph->type;
                icmp_code = icmph->code;

                break;
            }

#ifdef ENABLE_IPV6
            case IPPROTO_ICMPV6:
            {
                // Scan ICMPv6 header.
                struct icmp6hdr *icmp6h = l4_hdr;

                // Check ICMPv6 header.
                if (unlikely(icmp6h + 1 > (struct icmp6hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                l4_proto = IPPROTO_ICMPV6;

                icmp_type = icmp6h->icmp6_type;
                icmp_code = icmp6h->icmp6_code;

                break;
            }
#endif
        }
    }

    // Re-derive the IP header pointers from a fresh packet pointer.
    // Each layer-4/extension header parsing path above leaves the packet pointers with a different verified range.
    // Resetting them makes all paths look identical to the BPF verifier which keeps the verification of the filter rules cheap.
    void *data_fresh = (void *)(long)(*(volatile u32 *)&ctx->data);

    if (iph)
    {
        iph = data_fresh + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
#ifdef ENABLE_IPV6
    else
    {
        iph6 = data_fresh + sizeof(struct ethhdr);

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
#endif

    // Update client stats (PPS/BPS).
    u64 ip_pps = 0;
    u64 ip_bps = 0;

    u64 flow_pps = 0;
    u64 flow_bps = 0;

#if defined(ENABLE_RL_IP) || defined(ENABLE_RL_FLOW)
    if (iph)
    {
#ifdef ENABLE_RL_IP
        update_ip_stats(&ip_pps, &ip_bps, iph->saddr, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow_stats(&flow_pps, &flow_bps, iph->saddr, src_port, protocol, pkt_len, now);
#endif
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
#ifdef ENABLE_RL_IP
        update_ip6_stats(&ip_pps, &ip_bps, &src_ip6, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow6_stats(&flow_pps, &flow_bps, &src_ip6, src_port, protocol, pkt_len, now);
#endif
    }
#endif
#endif

    // Create rule context.
    rule_ctx_t rule = {0};
    rule.flow_pps = flow_pps;
    rule.flow_bps = flow_bps;
    rule.ip_pps = ip_pps;
    rule.ip_bps = ip_bps;
    rule.pkt_len = pkt_len;

#ifdef ENABLE_FILTER_LOGGING
    rule.now = now;
#endif

    rule.protocol = protocol;
    rule.l4_proto = l4_proto;
    rule.src_port = src_port;
    rule.dst_port = dst_port;
    rule.tcp_flags = tcp_flags;
    rule.icmp_type = icmp_type;
    rule.icmp_code = icmp_code;
    
    rule.iph = iph;
    rule.iph6 = iph6;

#ifdef USE_NEW_LOOP
    bpf_loop(MAX_FILTERS, process_rule, &rule, 0);
#else
#pragma unroll 30
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        if (process_rule(i, &rule))
        {
            break;
        }
    }
#endif

    if (rule.matched)
    {
        goto matched;
    }
#endif

    inc_pkt_stats(stats, STATS_TYPE_PASSED);
            
    return XDP_PASS;

#ifdef ENABLE_FILTERS
matched:
    if (rule.action == 0)
    {
        // Before dropping, update the block map.
        if (rule.block_time > 0)
        {
            u64 new_time = now + (rule.block_time * NANO_TO_SEC);
            
            if (iph)
            {
                bpf_map_update_elem(&map_block, &iph->saddr, &new_time, BPF_ANY);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_update_elem(&map_block6, &src_ip6, &new_time, BPF_ANY);
            }
#endif      
        }

        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }
    else
    {
        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
    }

    return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);