# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y
#CACHE_DISABLED = y

ifeq ($(CACHE_DISABLED),y)
  DISABLE_CACHE = -DDISABLE_CACHE
else
  DISABLE_CACHE = 
endif

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g $(DISABLE_CACHE) -DSIMPLE_LOCKS -DDEBUG -DMUTEX_MANUAL -DMUTEX_NONE -DDEBUGLEVEL=255 # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2 -DSIMPLE_LOCKS -DMUTEX_MANUAL -DMUTEX_NONE $(DISABLE_CACHE) -DBB_NO_OUTPUT
endif

#CFLAGS += $(DEBFLAGS) -DBB_FORCE_MAX_CAPACITY=1024
CFLAGS += $(DEBFLAGS) -DTRY_NO_DOUBLEBUFFER -DBB_CACHE_ASYNCWRITES -DBB_FAKE_ASYNC
#CFLAGS += $(DEBFLAGS) -DTRY_NO_DOUBLEBUFFER -DBB_CACHE_ASYNCWRITES
#CFLAGS += $(DEBFLAGS)
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
