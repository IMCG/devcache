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
sleep 1

#sudo mkfs.ext2 /dev/bb2
#sudo mkdir -p ./mnt_bb0 && sudo mount -t ext2 /dev/bb2 ./mnt_bb0

