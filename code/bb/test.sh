make

dd if=/dev/zero of=./file1 bs=512 count=20000
dd if=/dev/zero of=./file2 bs=512 count=20000
sudo losetup /dev/loop1 ./file1
sudo losetup /dev/loop2 ./file2

sudo insmod ./bbc.ko
sudo lsmod | grep bbc

sudo ./ioctl /dev/bb0 /dev/loop1 /dev/loop2 0
mkfs.ext2 /dev/bb0
mkdir -p ./mnt_bb0 && sudo mount -t ext2 /dev/bb0 ./mnt_bb0

