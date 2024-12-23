#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    struct ifreq ifr;
    int sockfd;
    
    // Check if interface name was provided
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        printf("Example: %s en0\n", argv[0]);
        return 1;
    }

    // Create a UDP socket for interface communication
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Clear the structure and copy interface name
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);

    // Get the interface flags
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        return 1;
    }

    // Print interface status
    printf("Interface %s status:\n", argv[1]);
    printf("UP: %s\n", (ifr.ifr_flags & IFF_UP) ? "yes" : "no");
    printf("RUNNING: %s\n", (ifr.ifr_flags & IFF_RUNNING) ? "yes" : "no");
    printf("LOOPBACK: %s\n", (ifr.ifr_flags & IFF_LOOPBACK) ? "yes" : "no");
    printf("POINTOPOINT: %s\n", (ifr.ifr_flags & IFF_POINTOPOINT) ? "yes" : "no");
    printf("MULTICAST: %s\n", (ifr.ifr_flags & IFF_MULTICAST) ? "yes" : "no");
    printf("BROADCAST: %s\n", (ifr.ifr_flags & IFF_BROADCAST) ? "yes" : "no");
    printf("PROMISC: %s\n", (ifr.ifr_flags & IFF_PROMISC) ? "yes" : "no");

    close(sockfd);
    return 0;
}
