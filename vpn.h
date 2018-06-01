//
// Created by fuji on 18-6-1.
//

#ifndef SIMPLE_VPN_VPN_H
#define SIMPLE_VPN_VPN_H

#include <netinet/in.h>
#include <netinet/ip.h>

struct vpn_route_entry {
    struct in_addr dest;
    struct in_addr netmask;
    struct in_addr gateway;
    struct vpn_route_entry *next;
};

struct vpn_route_entry *vpn_route_add(char *dest_str, char *netmask_str, char *gateway_str);

void *svpnd(void *);

void *dvpnd(void *);

#endif //SIMPLE_VPN_VPN_H
