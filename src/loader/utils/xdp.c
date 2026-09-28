#include <loader/utils/xdp.h>

/**
 * Finds a BPF map's FD.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
 */
int get_map_fd(struct xdp_program *prog, const char *map_name)
{
    int fd = -1;

    struct bpf_object *obj = xdp_program__bpf_obj(prog);

    if (obj == NULL)
    {
        fprintf(stderr, "Error finding BPF object from XDP program.\n");

        goto out;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", map_name);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}

/**
 * Custom print function for LibBPF that doesn't print anything (silent mode).
 * 
 * @param level The current LibBPF log level.
 * @param format The message format.
 * @param args Format arguments for the message.
 * 
 * @return void
 */
static int libbpf_silent(enum libbpf_print_level level, const char *format, va_list args)
{
    return 0;
}

/**
 * Sets custom LibBPF log mode.
 * 
 * @param silent If 1, disables LibBPF logging entirely.
 * 
 * @return void
 */
void set_libbpf_log_mode(int silent)
{
    if (silent)
    {
        libbpf_set_print(libbpf_silent);
    }
}

/**
 * Loads a BPF object file.
 * 
 * @param file_name The path to the BPF object file.
 * 
 * @return XDP program structure (pointer) or NULL.
 */
struct xdp_program *load_bpf_obj(const char *file_name)
{
    struct xdp_program *prog = xdp_program__open_file(file_name, "xdp_prog", NULL);

    if (prog == NULL)
    {
        // The main function handles this error.
        return NULL;
    }

    return prog;
}

/**
 * Retrieves BPF object from XDP program.
 * 
 * @param prog A pointer to the XDP program.
 * 
 * @return The BPF object.
 */
struct bpf_object* get_bpf_obj(struct xdp_program* prog)
{
    return xdp_program__bpf_obj(prog);
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param prog A pointer to the XDP program structure.
 * @param mode_used The mode being used.
 * @param ifidx The index to the interface to attach to.
 * @param detach If above 0, attempts to detach XDP program.
 * @param force_skb If set, forces the XDP program to run in SKB mode.
 * @param force_offload If set, forces the XDP program to run in offload mode.
 * 
 * @return 0 on success and 1 on error.
 */
int attach_xdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload)
{
    int err;

    u32 attach_mode = XDP_MODE_NATIVE;

    *mode = "DRV/native";

    if (force_offload)
    {
        *mode = "HW/offload";

        attach_mode = XDP_MODE_HW;
    }
    else if (force_skb)
    {
        *mode = "SKB/generic";
        
        attach_mode = XDP_MODE_SKB;
    }

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        if (detach)
        {
            err = xdp_program__detach(prog, ifidx, attach_mode, 0);
        }
        else
        {
            err = xdp_program__attach(prog, ifidx, attach_mode, 0);
        }

        if (err)
        {
            // Decrease mode.
            switch (attach_mode)
            {
                case XDP_MODE_HW:
                    attach_mode = XDP_MODE_NATIVE;
                    *mode = "DRV/native";

                    break;

                case XDP_MODE_NATIVE:
                    attach_mode = XDP_MODE_SKB;
                    *mode = "SKB/generic";

                    break;

                case XDP_MODE_SKB:
                    // Exit loop.
                    exit = 1;

                    *mode = NULL;
                    
                    break;
            }

            // Retry.
            continue;
        }
        
        // Success, so break current loop.
        break;
    }

    // If exit is set to 1 or smode is NULL, it indicates full failure.
    if (exit || *mode == NULL)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Deletes a filter.
 * 
 * The filters map is a (per-CPU) array map which doesn't support deleting elements, so the filter is cleared (zeroed) instead.
 * The XDP program stops processing filters once it reaches an unset filter.
 * 
 * @param map_filters The filters BPF map FD.
 * @param idx The filter index to delete.
 * 
 * @return 0 on success or the error value of bpf_map_update_elem().
 */
int delete_filter(int map_filters, u32 idx)
{
    int cpus = libbpf_num_possible_cpus();

    if (cpus < 1)
    {
        return cpus;
    }

    filter_t* filter_cpus = calloc(cpus, sizeof(filter_t));

    if (!filter_cpus)
    {
        return -ENOMEM;
    }

    int ret = bpf_map_update_elem(map_filters, &idx, filter_cpus, BPF_ANY);

    free(filter_cpus);

    return ret;
}

/**
 * Deletes all filters.
 * 
 * @param map_filters The filters BPF map FD.
 * 
 * @return void
 */
void delete_filters(int map_filters)
{
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        delete_filter(map_filters, i);
    }
}

/**
 * Checks if an optional integer config value (negative = unset) is within range.
 * 
 * @param val The value.
 * @param min The minimum value allowed.
 * @param max The maximum value allowed.
 * 
 * @return 1 if the value is unset or valid and 0 otherwise.
 */
static int is_opt_valid(s64 val, s64 min, s64 max)
{
    return val < 0 || (val >= min && val <= max);
}

/**
 * Converts a filter config rule into the filter structure used by the XDP program.
 * 
 * @param filter_cfg A pointer to the filter config rule.
 * @param cfg_idx The filter's index inside of the config (used for logging).
 * @param out A pointer to the filter structure to fill out.
 * 
 * @return 0 on success or -EINVAL on invalid filter settings.
 */
int build_filter(filter_rule_cfg_t* filter_cfg, int cfg_idx, filter_t* out)
{
    filter_t filter = {0};

    filter.set = filter_cfg->set;
    filter.id = cfg_idx;

    // Validate settings that would otherwise be truncated when stored inside of the BPF map.
    if (!is_opt_valid(filter_cfg->action, 0, 1) || !is_opt_valid(filter_cfg->block_time, 0, UINT32_MAX) ||
        !is_opt_valid(filter_cfg->ip.min_ttl, 0, 255) || !is_opt_valid(filter_cfg->ip.max_ttl, 0, 255) ||
        !is_opt_valid(filter_cfg->ip.min_len, 0, 65535) || !is_opt_valid(filter_cfg->ip.max_len, 0, 65535) ||
        !is_opt_valid(filter_cfg->ip.tos, 0, 255) ||
        !is_opt_valid(filter_cfg->icmp.code, 0, 255) || !is_opt_valid(filter_cfg->icmp.type, 0, 255))
    {
        return -EINVAL;
    }
    
    if (filter_cfg->enabled > -1)
    {
        filter.enabled = filter_cfg->enabled;
    }

    if (filter_cfg->log > -1)
    {
        filter.log = filter_cfg->log;
    }

    if (filter_cfg->action > -1)
    {
        filter.action = filter_cfg->action;
    }

    if (filter_cfg->block_time > -1)
    {
        filter.block_time = filter_cfg->block_time;
    }

#ifdef ENABLE_RL_IP
    if (filter_cfg->ip_pps > -1)
    {
        filter.do_ip_pps = 1;

        filter.ip_pps = (u64) filter_cfg->ip_pps;
    }

    if (filter_cfg->ip_bps > -1)
    {
        filter.do_ip_bps = 1;

        filter.ip_bps = (u64) filter_cfg->ip_bps;
    }
#endif

#ifdef ENABLE_RL_FLOW
    if (filter_cfg->flow_pps > -1)
    {
        filter.do_flow_pps = 1;

        filter.flow_pps = (u64) filter_cfg->flow_pps;
    }

    if (filter_cfg->flow_bps > -1)
    {
        filter.do_flow_bps = 1;

        filter.flow_bps = (u64) filter_cfg->flow_bps;
    }
#endif

    if (filter_cfg->ip.src_ip)
    {
        ip_range_t ip_range = parse_ip_range(filter_cfg->ip.src_ip);

        if (!ip_range.success)
        {
            return -EINVAL;
        }

        filter.ip.src_ip = ip_range.ip;
        filter.ip.src_cidr = ip_range.cidr;
    }

    if (filter_cfg->ip.dst_ip)
    {
        ip_range_t ip_range = parse_ip_range(filter_cfg->ip.dst_ip);

        if (!ip_range.success)
        {
            return -EINVAL;
        }

        filter.ip.dst_ip = ip_range.ip;
        filter.ip.dst_cidr = ip_range.cidr;
    }

#ifdef ENABLE_IPV6
    if (filter_cfg->ip.src_ip6)
    {
        if (parse_ip6_range(filter_cfg->ip.src_ip6, filter.ip.src_ip6, filter.ip.src_mask6) != 0)
        {
            return -EINVAL;
        }

        filter.ip.do_src_ip6 = 1;
    }

    if (filter_cfg->ip.dst_ip6)
    {
        if (parse_ip6_range(filter_cfg->ip.dst_ip6, filter.ip.dst_ip6, filter.ip.dst_mask6) != 0)
        {
            return -EINVAL;
        }

        filter.ip.do_dst_ip6 = 1;
    }
#endif
    if (filter_cfg->ip.min_ttl > -1)
    {
        filter.ip.do_min_ttl = 1;

        filter.ip.min_ttl = filter_cfg->ip.min_ttl;
    }

    if (filter_cfg->ip.max_ttl > -1)
    {
        filter.ip.do_max_ttl = 1;

        filter.ip.max_ttl = filter_cfg->ip.max_ttl;
    }

    if (filter_cfg->ip.min_len > -1)
    {
        filter.ip.do_min_len = 1;

        filter.ip.min_len = filter_cfg->ip.min_len;
    }

    if (filter_cfg->ip.max_len > -1)
    {
        filter.ip.do_max_len = 1;

        filter.ip.max_len = filter_cfg->ip.max_len;
    }

    if (filter_cfg->ip.tos > -1)
    {
        filter.ip.do_tos = 1;

        filter.ip.tos = filter_cfg->ip.tos;
    }

    if (filter_cfg->tcp.enabled > -1)
    {
        filter.tcp.enabled = filter_cfg->tcp.enabled;
    }

    port_range_t tcp_src_port_range = parse_port_range(filter_cfg->tcp.sport);

    // A port string that is set but can't be parsed must not silently turn into "any port".
    if (filter_cfg->tcp.sport && !tcp_src_port_range.success)
    {
        return -EINVAL;
    }

    if (tcp_src_port_range.success)
    {
        filter.tcp.do_sport_min = 1;
        filter.tcp.do_sport_max = 1;

        filter.tcp.sport_min = tcp_src_port_range.min;
        filter.tcp.sport_max = tcp_src_port_range.max;
    }

    port_range_t tcp_dst_port_range = parse_port_range(filter_cfg->tcp.dport);

    // A port string that is set but can't be parsed must not silently turn into "any port".
    if (filter_cfg->tcp.dport && !tcp_dst_port_range.success)
    {
        return -EINVAL;
    }

    if (tcp_dst_port_range.success)
    {
        filter.tcp.do_dport_min = 1;
        filter.tcp.do_dport_max = 1;

        filter.tcp.dport_min = tcp_dst_port_range.min;
        filter.tcp.dport_max = tcp_dst_port_range.max;
    }

    if (filter_cfg->tcp.urg > -1)
    {
        filter.tcp.do_urg = 1;

        filter.tcp.urg = filter_cfg->tcp.urg;
    }

    if (filter_cfg->tcp.ack > -1)
    {
        filter.tcp.do_ack = 1;

        filter.tcp.ack = filter_cfg->tcp.ack;
    }

    if (filter_cfg->tcp.rst > -1)
    {
        filter.tcp.do_rst = 1;

        filter.tcp.rst = filter_cfg->tcp.rst;
    }

    if (filter_cfg->tcp.psh > -1)
    {
        filter.tcp.do_psh = 1;

        filter.tcp.psh = filter_cfg->tcp.psh;
    }

    if (filter_cfg->tcp.syn > -1)
    {
        filter.tcp.do_syn = 1;

        filter.tcp.syn = filter_cfg->tcp.syn;
    }

    if (filter_cfg->tcp.fin > -1)
    {
        filter.tcp.do_fin = 1;

        filter.tcp.fin = filter_cfg->tcp.fin;
    }

    if (filter_cfg->tcp.ece > -1)
    {
        filter.tcp.do_ece = 1;

        filter.tcp.ece = filter_cfg->tcp.ece;
    }

    if (filter_cfg->tcp.cwr > -1)
    {
        filter.tcp.do_cwr = 1;

        filter.tcp.cwr = filter_cfg->tcp.cwr;
    }

    if (filter_cfg->udp.enabled > -1)
    {
        filter.udp.enabled = filter_cfg->udp.enabled;
    }

    port_range_t udp_src_port_range = parse_port_range(filter_cfg->udp.sport);

    // A port string that is set but can't be parsed must not silently turn into "any port".
    if (filter_cfg->udp.sport && !udp_src_port_range.success)
    {
        return -EINVAL;
    }

    if (udp_src_port_range.success)
    {
        filter.udp.do_sport_min = 1;
        filter.udp.do_sport_max = 1;

        filter.udp.sport_min = udp_src_port_range.min;
        filter.udp.sport_max = udp_src_port_range.max;
    }

    port_range_t udp_dst_port_range = parse_port_range(filter_cfg->udp.dport);

    // A port string that is set but can't be parsed must not silently turn into "any port".
    if (filter_cfg->udp.dport && !udp_dst_port_range.success)
    {
        return -EINVAL;
    }

    if (udp_dst_port_range.success)
    {
        filter.udp.do_dport_min = 1;
        filter.udp.do_dport_max = 1;

        filter.udp.dport_min = udp_dst_port_range.min;
        filter.udp.dport_max = udp_dst_port_range.max;
    }

    if (filter_cfg->icmp.enabled > -1)
    {
        filter.icmp.enabled = filter_cfg->icmp.enabled;
    }

    if (filter_cfg->icmp.code > -1)
    {
        filter.icmp.do_code = 1;

        filter.icmp.code = filter_cfg->icmp.code;
    }

    if (filter_cfg->icmp.type > -1)
    {
        filter.icmp.do_type = 1;

        filter.icmp.type = filter_cfg->icmp.type;
    }

    *out = filter;

    return 0;
}

/**
 * Updates a filter rule.
 * 
 * @param map_filters The filters BPF map FD.
 * @param filter_cfg A pointer to the filter config rule.
 * @param idx The filter index to insert or update.
 * @param cfg_idx The filter's index inside of the config (used for logging).
 * 
 * @return 0 on success, -EINVAL on invalid filter settings, or error value of bpf_map_update_elem().
 */
int update_filter(int map_filters, filter_rule_cfg_t* filter_cfg, int idx, int cfg_idx)
{
    if (!filter_cfg->enabled)
    {
        return 0;
    }

    filter_t filter;

    int ret = build_filter(filter_cfg, cfg_idx, &filter);

    if (ret != 0)
    {
        return ret;
    }

    // Per-CPU maps expect a value for every possible CPU.
    int cpus = libbpf_num_possible_cpus();

    if (cpus < 1)
    {
        return cpus;
    }

    filter_t* filter_cpus = calloc(cpus, sizeof(filter_t));

    if (!filter_cpus)
    {
        return -ENOMEM;
    }

    for (int j = 0; j < cpus; j++)
    {
        filter_cpus[j] = filter;
    }

    ret = bpf_map_update_elem(map_filters, &idx, filter_cpus, BPF_ANY);

    free(filter_cpus);

    return ret;
}

/**
 * Updates the filter's BPF map with current config settings.
 * 
 * Set and enabled filters are inserted in order starting from index 0 and all remaining indexes are cleared
 * so that filters removed from the config don't stay active inside of the XDP program.
 * 
 * @param map_filters The filter's BPF map FD.
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
 */
void update_filters(int map_filters, config__t *cfg)
{
    int ret;
    int cur_idx = 0;

    // Add a filter to the filter maps.
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_rule_cfg_t* filter = &cfg->filters[i];

        // Only insert set and enabled filters.
        if (!filter->set || !filter->enabled)
        {
            continue;
        }

        // Attempt to update filter.
        if ((ret = update_filter(map_filters, filter, cur_idx, i)) != 0)
        {
            if (ret == -EINVAL)
            {
                fprintf(stderr, "[WARNING] Skipping filter #%d due to invalid settings...\n", i + 1);
            }
            else
            {
                fprintf(stderr, "[WARNING] Failed to update filter #%d due to BPF update error (%d)...\n", i + 1, ret);
            }

            continue;
        }

        cur_idx++;
    }

    // Clear the rest of the filters (e.g. filters that were removed from the config).
    for (int i = cur_idx; i < MAX_FILTERS; i++)
    {
        if ((ret = delete_filter(map_filters, i)) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to clear filter at index %d (%d)...\n", i, ret);
        }
    }
}

/**
 * Pins a BPF map to the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return 0 on success or value of bpf_map__pin() on error.
 */
int pin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return -1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__pin(map, full_path);
}

/**
 * Unpins a BPF map from the file system.
 * 
 * @param obj A pointer to the BPF object.
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return
 */
int unpin_bpf_map(struct bpf_object* obj, const char* pin_dir, const char* map_name)
{
    struct bpf_map* map = bpf_object__find_map_by_name(obj, map_name);

    if (!map)
    {
        return 1;
    }

    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", XDP_MAP_PIN_DIR, map_name);

    return bpf_map__unpin(map, full_path);
}

/**
 * Retrieves a map FD on the file system (pinned).
 * 
 * @param pin_dir The pin directory.
 * @param map_name The map name.
 * 
 * @return The map FD or -1 on error.
 */
int get_map_fd_pin(const char* pin_dir, const char* map_name)
{
    char full_path[255];
    snprintf(full_path, sizeof(full_path), "%s/%s", pin_dir, map_name);

    return bpf_obj_get(full_path);
}

/**
 * Deletes IPv4 address from block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_block(int map_block, u32 ip)
{
    return bpf_map_delete_elem(map_block, &ip);
}

/**
 * Adds an IPv4 address to the block map.
 * 
 * @param map_block The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (nanoseconds since system boot).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_block(int map_block, u32 ip, u64 expires)
{
    return bpf_map_update_elem(map_block, &ip, &expires, BPF_ANY);
}

/**
 * Deletes IPv6 address from block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to remove.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem().
 */
int delete_block6(int map_block6, u128 ip)
{
    return bpf_map_delete_elem(map_block6, &ip);
}

/**
 * Adds an IPv6 address to the block map.
 * 
 * @param map_block6 The block map's FD.
 * @param ip The IP address to add.
 * @param expires When the block expires (nanoseconds since system boot).
 * 
 * @return 0 on success or error value of bpf_map_update_elem().
 */
int add_block6(int map_block6, u128 ip, u64 expires)
{
    return bpf_map_update_elem(map_block6, &ip, &expires, BPF_ANY);
}

/**
 * Deletes an IPv4 range from the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_delete_elem(). 
 */
int delete_range_drop(int map_range_drop, u32 net, u8 cidr)
{
    u32 bit_mask = get_cidr_mask(cidr);
    u32 start = net & bit_mask;

    lpm_trie_key_t key = {0};
    key.prefix_len = cidr;
    key.data = start;

    return bpf_map_delete_elem(map_range_drop, &key);
}

/**
 * Adds an IPv4 range to the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param net The network IP.
 * @param cidr The network's CIDR.
 * 
 * @return 0 on success or error value of bpf_map_update_elem(). 
 */
int add_range_drop(int map_range_drop, u32 net, u8 cidr)
{
    u32 bit_mask = get_cidr_mask(cidr);
    u32 start = net & bit_mask;

    lpm_trie_key_t key = {0};
    key.prefix_len = cidr;
    key.data = start;

    u64 val = ( (u64)bit_mask << 32 ) | start;

    return bpf_map_update_elem(map_range_drop, &key, &val, BPF_ANY);
}

/**
 * Updates IP ranges from config file.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param cfg A pointer to the config file
 * 
 * @return void
 */
void update_range_drops(int map_range_drop, config__t* cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (!range)
        {
            continue;
        }

        // Parse IP range string and return network IP and CIDR.
        ip_range_t t = parse_ip_range(range);

        if (!t.success)
        {
            fprintf(stderr, "[WARNING] Skipping invalid IP drop range '%s'...\n", range);

            continue;
        }

        int ret;

        if ((ret = add_range_drop(map_range_drop, t.ip, t.cidr)) != 0)
        {
            fprintf(stderr, "[WARNING] Failed to add IP drop range '%s' (%d)...\n", range, ret);
        }
    }
}

/**
 * Removes IP ranges that are in the old config, but not in the new config, from the drop map.
 * 
 * @param map_range_drop The IPv4 range drop map's FD.
 * @param old_cfg A pointer to the old config.
 * @param new_cfg A pointer to the new config.
 * 
 * @return void
 */
void remove_stale_range_drops(int map_range_drop, config__t* old_cfg, config__t* new_cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = old_cfg->drop_ranges[i];

        if (!range)
        {
            continue;
        }

        int found = 0;

        for (int j = 0; j < MAX_IP_RANGES; j++)
        {
            const char* new_range = new_cfg->drop_ranges[j];

            if (new_range && strcmp(range, new_range) == 0)
            {
                found = 1;

                break;
            }
        }

        if (found)
        {
            continue;
        }

        ip_range_t t = parse_ip_range(range);

        if (!t.success)
        {
            continue;
        }

        delete_range_drop(map_range_drop, t.ip, t.cidr);
    }
}