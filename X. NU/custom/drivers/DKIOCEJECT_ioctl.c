#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <paths.h>
#include <sys/disk.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s /dev/diskX\n", argv[0]);
        return 1;
    }

    // Open the disk device
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("Failed to open disk device");
        return 1;
    }

    // Attempt to eject the disk using ioctl
    if (ioctl(fd, DKIOCEJECT, NULL) < 0) {
        perror("Failed to eject disk");
        close(fd);
        return 1;
    }

    close(fd);
    printf("Disk ejected successfully\n");
    return 0;
}
