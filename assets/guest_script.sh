#!/bin/sh

PATH=/bin:/sbin:/usr/bin:/usr/sbin

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

echo "========== VM START =========="
date
uname -a
echo

echo "========== CPU =========="
cat /proc/cpuinfo

echo "========== MEMORY =========="
cat /proc/meminfo

echo "========== MODULES =========="
cat /proc/modules

echo "========== MOUNTS =========="
cat /proc/mounts

echo "========== CMDLINE =========="
cat /proc/cmdline

echo "========== DMESG =========="
dmesg

echo "========== PROCESS LIST =========="
ps

echo "========== FILESYSTEM SNAPSHOT =========="
find / -xdev 2>/dev/null | sort

echo "========== USERS =========="
echo "root:x:0:0"
echo "user:x:1000:1000"

echo "========== RESOURCES =========="
cat /proc/loadavg
cat /proc/stat

echo "========== MODIFIED FILES =========="
find / -xdev -mmin -5 2>/dev/null

echo "========== EXECUTABLE =========="
echo "__POC_NAME__"
echo "========== BINARY OUTPUT START =========="
./__POC_NAME__
EXITCODE=$?
echo "EXIT_CODE=$EXITCODE"
echo "========== BINARY OUTPUT END =========="
echo "========== SHUTDOWN =========="
poweroff -f