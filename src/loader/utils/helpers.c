#include <loader/utils/helpers.h>

/**
 * Prints help menu.
 * 
 * @return void
 */
void print_help_menu()
{
    printf("Usage: xdpfw [OPTIONS]\n\n");

    printf("  -c, --config         Config file location (default: /etc/xdpfw/xdpfw.conf).\n");
    printf("  -o, --offload        Load the XDP program in hardware/offload mode.\n");
    printf("  -s, --skb            Force the XDP program to load with SKB mode instead of DRV.\n");
    printf("  -t, --time           Duration to run the program (seconds). 0 or unset = infinite.\n");
    printf("  -l, --list           Print config details including filters (exits after execution).\n");
    printf("  -h, --help           Show this help message.\n\n");
    printf("  -v, --verbose        Override config's verbose value.\n");
    printf("      --log-file       Override config's log file value.\n");
    printf("  -i, --interface      Override config's interface value.\n");
    printf("  -u, --update-time    Override config's update time value.\n");
    printf("  -p, --pin-maps       Override config's pin maps value.\n");
    printf("  -n, --no-stats       Override config's no stats value.\n");
    printf("      --stats-ps       Override config's stats per second value.\n");
    printf("      --stdout-ut      Override config's stdout update time value.\n");
}

/**
 * Handles signals from user.
 * 
 * @param code Signal code.
 * 
 * @return void
 */
void hdl_signal(int code)
{
    cont = 0;
}

/**
 * Parses a CIDR/prefix length string.
 * 
 * @param str The prefix length string.
 * @param max The maximum prefix length allowed.
 * @param out Where to store the prefix length.
 * 
 * @return 0 on success or 1 on failure.
 */
static int parse_prefix_len(const char* str, int max, int* out)
{
    if (!str || *str == '\0')
    {
        return 1;
    }

    char* end = NULL;

    long val = strtol(str, &end, 10);

    if (end == str || *end != '\0' || val < 0 || val > max)
    {
        return 1;
    }

    *out = (int) val;

    return 0;
}

/**
 * Parses an IP string with CIDR support. Stores IP in network byte order in ip.ip and CIDR in ip.cidr.
 * 
 * The IP is masked with the CIDR. ret.success is set to 1 on success or 0 on failure (invalid IP or CIDR).
 * 
 * @param ip The IP string.
 * 
 * @return Returns an IP structure with IP and CIDR. 
 */
ip_range_t parse_ip_range(const char *ip)
{
    ip_range_t ret = {0};
    ret.cidr = 32;

    if (!ip)
    {
        return ret;
    }

    char ip_copy[INET_ADDRSTRLEN + 4];

    if (strlen(ip) >= sizeof(ip_copy))
    {
        return ret;
    }

    strcpy(ip_copy, ip);

    char* slash = strchr(ip_copy, '/');

    if (slash)
    {
        *slash = '\0';

        int cidr;

        if (parse_prefix_len(slash + 1, 32, &cidr) != 0)
        {
            return ret;
        }

        ret.cidr = (u8) cidr;
    }

    struct in_addr addr;

    if (inet_pton(AF_INET, ip_copy, &addr) != 1)
    {
        return ret;
    }

    ret.ip = addr.s_addr & get_cidr_mask(ret.cidr);
    ret.success = 1;

    return ret;
}

/**
 * Parses an IPv6 string with prefix support (e.g. 2001:db8::/32).
 * 
 * @param ip The IPv6 string.
 * @param addr Where to store the masked address (network byte order).
 * @param mask Where to store the prefix mask (network byte order).
 * 
 * @return 0 on success or 1 on failure.
 */
int parse_ip6_range(const char* ip, u32 addr[4], u32 mask[4])
{
    if (!ip)
    {
        return 1;
    }

    char ip_copy[INET6_ADDRSTRLEN + 5];

    if (strlen(ip) >= sizeof(ip_copy))
    {
        return 1;
    }

    strcpy(ip_copy, ip);

    int prefix = 128;

    char* slash = strchr(ip_copy, '/');

    if (slash)
    {
        *slash = '\0';

        if (parse_prefix_len(slash + 1, 128, &prefix) != 0)
        {
            return 1;
        }
    }

    struct in6_addr in;

    if (inet_pton(AF_INET6, ip_copy, &in) != 1)
    {
        return 1;
    }

    u32 words[4];
    memcpy(words, in.s6_addr, sizeof(words));

    for (int i = 0; i < 4; i++)
    {
        int bits = prefix - (i * 32);

        if (bits > 32)
        {
            bits = 32;
        }
        else if (bits < 0)
        {
            bits = 0;
        }

        mask[i] = get_cidr_mask((u8) bits);
        addr[i] = words[i] & mask[i];
    }

    return 0;
}

/**
 * Converts a CIDR (0 - 32) to a bit mask in network byte order.
 * 
 * @param cidr The CIDR.
 * 
 * @return The bit mask in network byte order.
 */
u32 get_cidr_mask(u8 cidr)
{
    if (cidr == 0)
    {
        return 0;
    }

    if (cidr > 32)
    {
        cidr = 32;
    }

    return htonl(0xFFFFFFFFu << (32 - cidr));
}

/**
 * Retrieves protocol name by ID.
 * 
 * @param id The protocol ID
 * 
 * @return The protocol string. 
 */
const char* get_protocol_str_by_id(int id)
{
    switch (id)
    {
        case IPPROTO_TCP:
            return "TCP";

        case IPPROTO_UDP:
            return "UDP";
        
        case IPPROTO_ICMP:
            return "ICMP";

        case IPPROTO_ICMPV6:
            return "ICMPv6";
    }

    return "N/A";
}

/**
 * Prints tool name and author.
 * 
 * @return void
 */
void print_tool_info()
{
    printf(
        " __  ______  ____    _____ _                        _ _ \n"
        " \\ \\/ /  _ \\|  _ \\  |  ___(_)_ __ _____      ____ _| | |\n"
        "  \\  /| | | | |_) | | |_  | | '__/ _ \\ \\ /\\ / / _` | | |\n"
        "  /  \\| |_| |  __/  |  _| | | | |  __/\\ V  V / (_| | | |\n"
        " /_/\\_\\____/|_|     |_|   |_|_|  \\___| \\_/\\_/ \\__,_|_|_|\n"
        "\n\n"
    );
}

/**
 * Retrieves nanoseconds since system boot.
 * 
 * This uses CLOCK_MONOTONIC which is the same clock bpf_ktime_get_ns() uses inside of the XDP program.
 * 
 * @return The current nanoseconds since the system last booted.
 */
u64 get_boot_nano_time()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0;
    }

    return ((u64) ts.tv_sec * 1000000000ULL) + (u64) ts.tv_nsec;
}

/**
 * Parses a port range string and returns the minimum and maximum port.
 * 
 * @param range_str The port range string.
 * 
 * @return The port range as port_range_t type. Fields will be set to 0 on failure.
 */
port_range_t parse_port_range(const char* range_str)
{
    port_range_t ret = {0};

    if (!range_str)
    {
        return ret;
    }

    // Copy range string.
    char range_str_copy[24];
    strncpy(range_str_copy, range_str, sizeof(range_str_copy) - 1);
    range_str_copy[sizeof(range_str_copy) - 1] = '\0';

    // First scan for port ranges with ":".
    char* start = range_str_copy;
    char* end = strchr(range_str_copy, '-');

    if (!end)
    {
        end = strchr(range_str_copy, ':');
    }

    if (end)
    {
        *end = '\0';
        end++;
    }

    char *end_ptr = NULL;

    long min = strtol(start, &end_ptr, 10);

    if (end_ptr == start || (*end_ptr != '\0' && !isspace((unsigned char)*end_ptr)))
    {
        return ret;
    }

    long max = min;

    if (end)
    {
        max = strtol(end, &end_ptr, 10);

        if (end_ptr == end || (*end_ptr != '\0' && !isspace((unsigned char)*end_ptr)))
        {
            return ret;
        }
    }

    // Validate the port range.
    if (min < 0 || min > 65535 || max < 0 || max > 65535 || min > max)
    {
        return ret;
    }

    ret.min = (u16) min;
    ret.max = (u16) max;

    ret.success = 1;

    return ret;
}