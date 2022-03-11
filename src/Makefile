obj-m := ti-mfa.o
ti-mfa-m := hook.o netlink.o ti_mfa_algo.o utils.o

INCLUDES = -I $(PWD)/include
CFLAGS = "$(INCLUDES) -D DEBUG -Wall"
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD:= $(shell pwd)

.phony: all install clean

all:
	make -C $(KERNELDIR) EXTRA_CFLAGS=${CFLAGS} M=$(PWD) modules

install: all
	sudo rmmod ti_mfa || true
	sudo insmod ti-mfa.ko

clean:
	make -C $(KERNELDIR) M=$(PWD) clean