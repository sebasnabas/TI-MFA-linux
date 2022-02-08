obj-m := ti-mfa.o
ti-mfa-m := hook.o

INCLUDES = -I $(PWD)/include
CFLAGS = "$(INCLUDES) -D DEBUG -Wall"
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD:= $(shell pwd)

.phony: all clean

all:
	make -C $(KERNELDIR) EXTRA_CFLAGS=${CFLAGS} M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean