#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sched.h>

int main(void)
{
    int efd = eventfd(0, 0);
    int ep = epoll_create1(0);

    void *page = mmap(
        NULL,
        0x1000,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (page == MAP_FAILED)
        return 1;

    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks))
        return 1;

    write(socks[0], "AAAA", 4);

    char buf[16];
    read(socks[1], buf, sizeof(buf));

    if (unshare(CLONE_NEWNS | CLONE_NEWIPC) < 0)
        perror("unshare");

    munmap(page, 0x1000);

    close(socks[0]);
    close(socks[1]);
    close(efd);
    close(ep);

    puts("POC_OK");
    return 0;
}