#!/bin/sh

dd if=/dev/zero of=/dev/sbulla count=10000
dd if=/dev/zero of=/dev/sbullb count=10000
dd if=/dev/zero of=/dev/sbullc count=10000
dd if=/dev/zero of=/dev/sbulld count=10000

insmod bb.ko
sleep 1

./ioctl /dev/bb0 /dev/sbulla /dev/sbullb
mkfs.ext2 /dev/bb0
mount -t ext2 /dev/bb0 /mnt/bb
cp /home/ahsen/test.dat /mnt/bb
diff /home/ahsen/test.dat /mnt/bb
umount /mnt/bb
hexdump /dev/bb0 > /dev/null
rmmod bb.ko
sleep 1

insmod bb.ko
sleep 1
./ioctl /dev/bb0 /dev/sbullb /dev/sbulla
mount -t ext2 /dev/bb0 /mnt/bb
diff /home/ahsen/test.dat /mnt/bb
umount /mnt/bb
