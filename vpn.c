//
// Created by fuji on 18-6-1.
//

#include <errno.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>

#include <linux/if_packet.h>

#include "vpn.h"

#define BUF_LEN 2048

// read-only after setup
static struct vpn_route_entry *vpn_route_head = NULL;

static struct vpn_route_entry *vpn_route_lookup(struct in_addr addr, struct in_addr netmask) {
    struct vpn_route_entry *entry;
    for (entry = vpn_route_head; entry != NULL; entry = entry->next)
        if (addr.s_addr == entry->dest.s_addr &&
            netmask.s_addr == entry->netmask.s_addr)
            break;
    return entry;
}

static struct vpn_route_entry *vpn_route_match(struct in_addr addr) {
    struct vpn_route_entry *entry;
    for (entry = vpn_route_head; entry != NULL; entry = entry->next)
        if ((addr.s_addr & entry->netmask.s_addr) == entry->dest.s_addr)
            break;
    return entry;
}

static struct vpn_route_entry *vpn_route_alloc(struct in_addr dest, struct in_addr netmask,
                                               struct in_addr gateway) {
    struct vpn_route_entry *entry;

    entry = malloc(sizeof(*entry));
    entry->dest = dest;
    entry->netmask = netmask;
    entry->gateway = gateway;

    // add entry to route_list
    entry->next = vpn_route_head;
    vpn_route_head = entry;

    return entry;
}

struct vpn_route_entry *vpn_route_add(char *dest_str, char *netmask_str, char *gateway_str) {
    struct in_addr dest, netmask, gateway;

    if (inet_aton(dest_str, &dest) == 0) {
        fprintf(stderr, "vpn_route_add: invalid ip %s\n", dest_str);
        return NULL;
    }
    if (inet_aton(netmask_str, &netmask) == 0) {
        fprintf(stderr, "vpn_route_add: invalid netmask %s\n", netmask_str);
        return NULL;
    }

    // make sure the dest is not a particular ip address
    dest.s_addr = dest.s_addr & netmask.s_addr;
    if (vpn_route_lookup(dest, netmask) != NULL) {
        fprintf(stderr, "vpn_route_add: %s %s already exists\n", dest_str, netmask_str);
        return NULL;
    }

    if (inet_aton(gateway_str, &gateway) == 0) {
        fprintf(stderr, "vpn_route_add: invalid gateway %s\n", gateway_str);
        return NULL;
    }

    return vpn_route_alloc(dest, netmask, gateway);
}

/*
static int local_ip(struct in_addr addr) {
    struct ifaddrs *if_addrs;
    int found = 0;

    getifaddrs(&if_addrs);
    struct ifaddrs *ifap;
    for (ifap = if_addrs; ifap != NULL; ifap = ifap->ifa_next) {
        if (ifap->ifa_addr && (ifap->ifa_flags & IFF_UP) && ifap->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *) (ifap->ifa_addr);
            if (addr.s_addr == sa->sin_addr.s_addr) {
                found = 1;
                break;
            }
        }
    }
    freeifaddrs(if_addrs);
    return found;
}
*/

void *dvpnd(void *arg) {
    unsigned char buffer[BUF_LEN];

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_IPIP);
    if (sockfd < 0) {
        fprintf(stderr, "dvpnd: socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // set IP_HDRINCL option
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr, "dvpnd: setsockopt: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ssize_t nbytes;
    while ((nbytes = recv(sockfd, buffer, BUF_LEN, 0)) > 0) {
        if (nbytes < sizeof(struct ip))
            continue;
        struct ip *iph = (struct ip *) buffer;
        struct ip *iph1 = (struct ip *) ((char *) iph + iph->ip_hl * 4);
        // TODO look into iph1 and check the dst field
        struct sockaddr_in daddr = {
                .sin_family = AF_INET,
                .sin_addr = iph1->ip_dst,
        };
        if (sendto(sockfd, iph1, ntohs(iph1->ip_len), 0,
                   (struct sockaddr *) &daddr, sizeof(daddr)) < 0) {
            fprintf(stderr, "dvpnd: sendto: %s\n", strerror(errno));
        }
    }

    if (close(sockfd) < 0)
        fprintf(stderr, "vpnd: close: %s\n", strerror(errno));

    return NULL;
}

static int vpn_send(void *buffer, size_t nbytes, struct in_addr dest) {
    // add outer ip header and send this out
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_IPIP);
    if (sockfd < 0) {
        fprintf(stderr, "vpn_send: socket: %s\n", strerror(errno));
        return -1;
    }
    // TODO maybe we should build ip header on our own

    struct sockaddr_in daddr = {
            .sin_family = AF_INET,
            .sin_addr = dest,
    };

    if (sendto(sockfd, buffer, nbytes, 0,
               (struct sockaddr *) &daddr, sizeof(daddr)) < 0) {
        fprintf(stderr, "vpn_send: sendto: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    if (close(sockfd) < 0) {
        fprintf(stderr, "vpn_send: close: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void *svpnd(void *arg) {
    unsigned char buffer[BUF_LEN];

    int sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (sockfd < 0) {
        fprintf(stderr, "svpnd: socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ssize_t nbytes;
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);

    while ((nbytes = recvfrom(sockfd, buffer, BUF_LEN, 0,
                              (struct sockaddr *) &addr, &addr_len)) > 0) {

        // we only care about incoming uni-cast packet
        if (addr.sll_hatype != ARPHRD_ETHER ||
            addr.sll_pkttype != PACKET_HOST)
            continue;

        if (nbytes < sizeof(struct ip))
            continue;
        struct ip *iph = (struct ip *) buffer;
        // TODO should we check ip checksum?
        // check if dst is in vpn_route_table
        struct vpn_route_entry *vr_entry = vpn_route_match(iph->ip_dst);
        if (vr_entry)
            vpn_send(iph, ntohs(iph->ip_len), vr_entry->gateway);
        // discard packets not in route table
    }

    if (close(sockfd) < 0)
        fprintf(stderr, "vpnd: close: %s\n", strerror(errno));

    return NULL;
}
