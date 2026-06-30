#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main(void)
{
    if (mount("proc", "/proc", "proc", 0, NULL))
    perror("mount proc");

    if (mount("sysfs", "/sys", "sysfs", 0, NULL))
        perror("mount sysfs");

    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL))
        perror("mount devtmpfs");

    puts("========== VM START ==========");
    fflush(stdout);

    system("/bin/sh /audit.sh");

    sync();

    _exit(0);
}