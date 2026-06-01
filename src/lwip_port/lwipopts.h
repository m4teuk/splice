// lwIP configuration for splice: a single-threaded (NO_SYS), IPv6-only stack
// driven by the path manager. We use the C library allocator so there are no
// memory pools to hand-size, and the raw TCP API (no netconn/sockets).
#ifndef SPL_LWIPOPTS_H
#define SPL_LWIPOPTS_H

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_NETIF_API 0

// Use malloc/free for both the heap and the memp pools — no manual sizing.
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#define MEM_ALIGNMENT 8  // 64-bit host
#define MEM_SIZE (256 * 1024)

// IPv6 only (ULA addressing inside the tunnel).
#define LWIP_IPV4 0
#define LWIP_IPV6 1
#define LWIP_IPV6_AUTOCONFIG 0
#define LWIP_IPV6_DHCP6 0
#define LWIP_ICMP6 1
#define LWIP_IPV6_MLD 1

#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_RAW 0
#define LWIP_DNS 0

#define LWIP_SINGLE_NETIF 1
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK 0
// Loop packets addressed to our own tunnel address back internally (also lets us
// unit-test TCP within a single process). Processed via netif_poll().
#define LWIP_NETIF_LOOPBACK 1
#define LWIP_HAVE_LOOPIF 0

// Inner MTU leaves headroom for WireGuard + the outer UDP/IP encapsulation.
#define TCP_MSS 1200
#define TCP_WND (8 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)

#define LWIP_STATS 0
#define LWIP_DEBUG 0

#endif  // SPL_LWIPOPTS_H
