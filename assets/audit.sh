#!/bin/sh

echo "========== DATE =========="
date

echo "========== UNAME =========="
uname -a

echo "========== MODULES =========="
cat /proc/modules

echo "========== MEMINFO =========="
cat /proc/meminfo

echo "========== DMESG =========="
dmesg

echo "========== PROCESSES =========="
ps

echo "========== FILES =========="
find / -xdev

echo "========== END =========="