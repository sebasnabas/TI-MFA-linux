obj-m := ti-mfa.o
ti-mfa-m := utils.o hook.o

INCLUDES="-I $(PWD)/include"

all:
	make -C /lib/modules/$(shell uname -r)/build EXTRA_CFLAGS=${INCLUDES} M=$(PWD) modules

.phony: all clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
