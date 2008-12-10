#!/bin/bash

set -x

if [[ `lsmod | grep bbc` ]]; then 
echo "module already loaded";
else
make clean && make

sudo insmod ./bbc.ko
sleep 2
sudo lsmod | grep bbc

fi;

sudo ./ioctl /dev/bb0 /dev/ram0 /dev/ram1 3
sleep 1

if [[ $DO_MKFS ]]; then
sudo mkfs.ext2 /dev/bb0
sudo mkdir -p ./mnt_bb0 && sudo mount -t ext2 /dev/bb0 ./mnt_bb0
fi;

