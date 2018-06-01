#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vpn.h"

void usage(void) {
    fprintf(stderr, "Usage: simple-vpn route\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    FILE *fp;
    int n;

    char addr_str[16];
    char netmask_str[16];
    char gateway_str[16];

    if (argc < 2)
        usage();

    // setup route table
    if ((fp = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "simple-vpn: fopen: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    while ((n = fscanf(fp, "%15s %15s %15s", addr_str, netmask_str, gateway_str)) == 3) {
        // add default route for this entry
        if (vpn_route_add(addr_str, netmask_str, gateway_str) == NULL)
            exit(EXIT_FAILURE);
    }
    if (n != EOF) {
        fprintf(stderr, "simple-vpn: route config error\n");
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    pthread_t svpnd_tid;
    pthread_t dvpnd_tid;
    // start svpn daemon
    if (pthread_create(&svpnd_tid, NULL, svpnd, NULL) != 0) {
        fprintf(stderr, "simple-vpn: can't start svpnd\n");
        exit(EXIT_FAILURE);
    }
    // start dvpn daemon
    if (pthread_create(&dvpnd_tid, NULL, dvpnd, NULL) != 0) {
        fprintf(stderr, "simple-vpn: can't start dvpnd\n");
        exit(EXIT_FAILURE);
    }

    pthread_join(svpnd_tid, NULL);
    pthread_join(dvpnd_tid, NULL);

    exit(EXIT_SUCCESS);
}
