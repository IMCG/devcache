#!/bin/bash
set +x

if [[ `lsmod | grep bbc` ]]; then 
echo "module already loaded";
else
make clean && make

sudo insmod ./bbc.ko
sleep 2
sudo lsmod | grep bbc

fi;

sudo ./ioctl /dev/bb2 /dev/sdb /dev/sda 3
#sudo ./ioctl /dev/bb2 /dev/sdb /dev/sda 1
sleep 1

sync
sudo echo 3 > /proc/sys/vm/drop_caches

if [[ $DO_MKFS ]]; then
sudo mkfs.ext2 /dev/bb2
sudo mkdir -p ./mnt_bb2 && sudo mount -t ext2 /dev/bb2 ./mnt_bb2
fi;

