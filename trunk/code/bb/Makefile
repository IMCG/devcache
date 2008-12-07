# Comment/uncomment the following line to disable/enable debugging
DEBUG = y


# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSIMPLE_LOCKS -DBB_DEBUG -DDEBUG -DMUTEX_MANUAL -DMUTEX_NONE -DDEBUGLEVEL=255 # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2 -DSIMPLE_LOCKS -DMUTEX_MANUAL -DMUTEX_NONE
endif

CFLAGS += $(DEBFLAGS)
CFLAGS += -I.. -I../Cache/Cache/

ifneq ($(KERNELRELEASE),)
# call from kernel build system

bbc-objs	:= ../Cache/Cache/Cache.o bb.o
obj-m		:= bbc.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	$(MAKE) ioctl

endif

ioctl: ioctl.c
	$(CC) -o ioctl ioctl.c

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions ioctl ../Cache/Cache/*.o ../Cache/Cache/.Cache.* Module.symvers file1 file2

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
