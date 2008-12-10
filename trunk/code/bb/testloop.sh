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

rm -rf ./file1 ./file2
dd if=/dev/zero of=./file1 bs=512 count=20000
dd if=/dev/zero of=./file2 bs=512 count=20000
chmod 777 ./file1
chmod 777 ./file2
sudo losetup -d /dev/loop5
sudo losetup -d /dev/loop6
sudo losetup /dev/loop5 ./file1
sudo losetup /dev/loop6 ./file2

sudo ./ioctl /dev/bb1 /dev/loop5 /dev/loop6 3
sleep 1

if [[ $DO_MKFS ]]; then
sudo mkfs.ext2 /dev/bb1
sudo mkdir -p ./mnt_bb1 && sudo mount -t ext2 /dev/bb1 ./mnt_bb1
fi;

