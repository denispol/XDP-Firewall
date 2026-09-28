#include <xdp/utils/rule.h>

#ifdef ENABLE_FILTERS
// Bit positions of TCP flags inside of the TCP flags byte.
#define TCP_FLAG_BIT_FIN 0
#define TCP_FLAG_BIT_SYN 1
#define TCP_FLAG_BIT_RST 2
#define TCP_FLAG_BIT_PSH 3
#define TCP_FLAG_BIT_ACK 4
#define TCP_FLAG_BIT_URG 5
#define TCP_FLAG_BIT_ECE 6
#define TCP_FLAG_BIT_CWR 7

#define TCP_FLAG(flags, bit) (((flags) >> (bit)) & 1)

/**
 * Checks ports against a filter's port range options.
 * 
 * @param do_sport_min Whether to check the minimum source port.
 * @param sport_min The minimum source port.
 * @param do_sport_max Whether to check the maximum source port.
 * @param sport_max The maximum source port.
 * @param do_dport_min Whether to check the minimum destination port.
 * @param dport_min The minimum destination port.
 * @param do_dport_max Whether to check the maximum destination port.
 * @param dport_max The maximum destination port.
 * @param ctx A pointer to the rule context.
 * 
 * @return 1 on match or 0 on no match.
 */
static __always_inline int match_ports(int do_sport_min, u16 sport_min, int do_sport_max, u16 sport_max, int do_dport_min, u16 dport_min, int do_dport_max, u16 dport_max, rule_ctx_t* ctx)
{
    u16 sport = ntohs(ctx->src_port);
    u16 dport = ntohs(ctx->dst_port);

    if (do_sport_min && sport < sport_min)
    {
        return 0;
    }

    if (do_sport_max && sport > sport_max)
    {
        return 0;
    }

    if (do_dport_min && dport < dport_min)
    {
        return 0;
    }

    if (do_dport_max && dport > dport_max)
    {
        return 0;
    }

    return 1;
}

/**
 * Checks the packet's TCP header information against a filter's TCP options.
 * 
 * @param filter A pointer to the filter.
 * @param ctx A pointer to the rule context.
 * 
 * @return 1 on match or 0 on no match.
 */
static __always_inline int match_tcp(filter_t* filter, rule_ctx_t* ctx)
{
    if (!match_ports(filter->tcp.do_sport_min, filter->tcp.sport_min, filter->tcp.do_sport_max, filter->tcp.sport_max, filter->tcp.do_dport_min, filter->tcp.dport_min, filter->tcp.do_dport_max, filter->tcp.dport_max, ctx))
    {
        return 0;
    }

    u8 flags = ctx->tcp_flags;

    // URG flag.
    if (filter->tcp.do_urg && filter->tcp.urg != TCP_FLAG(flags, TCP_FLAG_BIT_URG))
    {
        return 0;
    }

    // ACK flag.
    if (filter->tcp.do_ack && filter->tcp.ack != TCP_FLAG(flags, TCP_FLAG_BIT_ACK))
    {
        return 0;
    }

    // RST flag.
    if (filter->tcp.do_rst && filter->tcp.rst != TCP_FLAG(flags, TCP_FLAG_BIT_RST))
    {
        return 0;
    }

    // PSH flag.
    if (filter->tcp.do_psh && filter->tcp.psh != TCP_FLAG(flags, TCP_FLAG_BIT_PSH))
    {
        return 0;
    }

    // SYN flag.
    if (filter->tcp.do_syn && filter->tcp.syn != TCP_FLAG(flags, TCP_FLAG_BIT_SYN))
    {
        return 0;
    }

    // FIN flag.
    if (filter->tcp.do_fin && filter->tcp.fin != TCP_FLAG(flags, TCP_FLAG_BIT_FIN))
    {
        return 0;
    }

    // ECE flag.
    if (filter->tcp.do_ece && filter->tcp.ece != TCP_FLAG(flags, TCP_FLAG_BIT_ECE))
    {
        return 0;
    }

    // CWR flag.
    if (filter->tcp.do_cwr && filter->tcp.cwr != TCP_FLAG(flags, TCP_FLAG_BIT_CWR))
    {
        return 0;
    }

    return 1;
}

/**
 * Checks the packet's UDP header information against a filter's UDP options.
 * 
 * @param filter A pointer to the filter.
 * @param ctx A pointer to the rule context.
 * 
 * @return 1 on match or 0 on no match.
 */
static __always_inline int match_udp(filter_t* filter, rule_ctx_t* ctx)
{
    return match_ports(filter->udp.do_sport_min, filter->udp.sport_min, filter->udp.do_sport_max, filter->udp.sport_max, filter->udp.do_dport_min, filter->udp.dport_min, filter->udp.do_dport_max, filter->udp.dport_max, ctx);
}

/**
 * Checks an ICMP type and code against a filter's ICMP options.
 * 
 * @param filter A pointer to the filter.
 * @param type The ICMP type.
 * @param code The ICMP code.
 * 
 * @return 1 on match or 0 on no match.
 */
static __always_inline int match_icmp(filter_t* filter, u8 type, u8 code)
{
    // Code.
    if (filter->icmp.do_code && filter->icmp.code != code)
    {
        return 0;
    }

    // Type.
    if (filter->icmp.do_type && filter->icmp.type != type)
    {
        return 0;
    }

    return 1;
}

/**
 * Processes a filter rule.
 * 
 * @param idx The rule index.
 * @param data A pointer to the rule context.
 * 
 * @return 1 to break the loop or 0 to continue.
 */
static __always_inline long process_rule(u32 idx, void* data)
{
    rule_ctx_t* ctx = data;

    filter_t *filter = bpf_map_lookup_elem(&map_filters, &idx);

    if (!filter || !filter->set)
    {
        return 1;
    }

    // Disabled filters are skipped (the loader doesn't insert them, but be safe).
    if (!filter->enabled)
    {
        return 0;
    }

#ifdef ENABLE_RL_IP
    // Check source IP rate limits.
    if (filter->do_ip_pps && ctx->ip_pps < filter->ip_pps)
    {
        return 0;
    }

    if (filter->do_ip_bps && ctx->ip_bps < filter->ip_bps)
    {
        return 0;
    }
#endif

#ifdef ENABLE_RL_FLOW
    // Check source flow rate limits.
    if (filter->do_flow_pps && ctx->flow_pps < filter->flow_pps)
    {
        return 0;
    }

    if (filter->do_flow_bps && ctx->flow_bps < filter->flow_bps)
    {
        return 0;
    }
#endif

    // Max packet length.
    if (filter->ip.do_max_len && filter->ip.max_len < ctx->pkt_len)
    {
        return 0;
    }

    // Min packet length.
    if (filter->ip.do_min_len && filter->ip.min_len > ctx->pkt_len)
    {
        return 0;
    }

    // Match IP settings.
    if (ctx->iph)
    {
        // Source address.
        if (filter->ip.src_ip)
        {
            if (filter->ip.src_cidr == 32 && ctx->iph->saddr != filter->ip.src_ip)
            {
                return 0;
            }

            if (!is_ip_in_range(ctx->iph->saddr, filter->ip.src_ip, filter->ip.src_cidr))
            {
                return 0;
            }
        }

        // Destination address.
        if (filter->ip.dst_ip)
        {
            if (filter->ip.dst_cidr == 32 && ctx->iph->daddr != filter->ip.dst_ip)
            {
                return 0;
            }
            
            if (!is_ip_in_range(ctx->iph->daddr, filter->ip.dst_ip, filter->ip.dst_cidr))
            {
                return 0;
            }
        }

#if defined(ENABLE_IPV6) && defined(ALLOW_SINGLE_IP_V4_V6)
        if (filter->ip.do_src_ip6 || filter->ip.do_dst_ip6)
        {
            return 0;
        }
#endif

        // TOS.
        if (filter->ip.do_tos && filter->ip.tos != ctx->iph->tos)
        {
            return 0;
        }

        // Max TTL.
        if (filter->ip.do_max_ttl && filter->ip.max_ttl < ctx->iph->ttl)
        {
            return 0;
        }

        // Min TTL.
        if (filter->ip.do_min_ttl && filter->ip.min_ttl > ctx->iph->ttl)
        {
            return 0;
        }
    }
#ifdef ENABLE_IPV6
    else if (ctx->iph6)
    {
        // Source address (with prefix support).
        if (filter->ip.do_src_ip6)
        {
#pragma unroll
            for (int i = 0; i < 4; i++)
            {
                if ((ctx->iph6->saddr.in6_u.u6_addr32[i] & filter->ip.src_mask6[i]) != filter->ip.src_ip6[i])
                {
                    return 0;
                }
            }
        }

        // Destination address (with prefix support).
        if (filter->ip.do_dst_ip6)
        {
#pragma unroll
            for (int i = 0; i < 4; i++)
            {
                if ((ctx->iph6->daddr.in6_u.u6_addr32[i] & filter->ip.dst_mask6[i]) != filter->ip.dst_ip6[i])
                {
                    return 0;
                }
            }
        }

#ifdef ALLOW_SINGLE_IP_V4_V6
        if (filter->ip.src_ip != 0 || filter->ip.dst_ip != 0)
        {
            return 0;
        }
#endif

        // Traffic class (IPv6 equivalent of TOS).
        if (filter->ip.do_tos && filter->ip.tos != (u8)((ctx->iph6->priority << 4) | (ctx->iph6->flow_lbl[0] >> 4)))
        {
            return 0;
        }

        // Max TTL length.
        if (filter->ip.do_max_ttl && filter->ip.max_ttl < ctx->iph6->hop_limit)
        {
            return 0;
        }

        // Min TTL length.
        if (filter->ip.do_min_ttl && filter->ip.min_ttl > ctx->iph6->hop_limit)
        {
            return 0;
        }
    }
#endif

    // Check layer-4 matches.
    // If one or more protocols are enabled on the filter, the packet must match at least one of them.
    if (filter->tcp.enabled || filter->udp.enabled || filter->icmp.enabled)
    {
        int l4_matched = 0;

        switch (ctx->l4_proto)
        {
            case IPPROTO_TCP:
                l4_matched = filter->tcp.enabled && match_tcp(filter, ctx);

                break;

            case IPPROTO_UDP:
                l4_matched = filter->udp.enabled && match_udp(filter, ctx);

                break;

            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                l4_matched = filter->icmp.enabled && match_icmp(filter, ctx->icmp_type, ctx->icmp_code);

                break;
        }

        if (!l4_matched)
        {
            return 0;
        }
    }

#ifdef ENABLE_FILTER_LOGGING
    if (filter->log > 0)
    {
        log_filter_msg(ctx->iph, ctx->iph6, ctx->src_port, ctx->dst_port, ctx->protocol, ctx->now, ctx->ip_pps, ctx->ip_bps, ctx->flow_pps, ctx->flow_bps, ctx->pkt_len, filter->id, filter->action, filter->block_time);
    }
#endif
    
    // Matched.
    ctx->matched = 1;
    ctx->action = filter->action;
    ctx->block_time = filter->block_time;

    return 1;
}
#endif