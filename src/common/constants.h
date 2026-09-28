#pragma once

#define MAX_PCKT_LENGTH 65535
#define NANO_TO_SEC 1000000000

// The maximum amount of IPv6 extension headers the XDP program walks through to find the layer-4 header.
#define IPV6_MAX_EXT_HDRS 6