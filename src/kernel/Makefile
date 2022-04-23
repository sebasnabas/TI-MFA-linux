obj-m := ti-mfa.o
ti-mfa-m := hook.o mpls.o ti_mfa_algo.o utils.o genl.o routes.o

GEN_COMPILE_COMMANDS := ../../generate_compdb.py

INCLUDES = -I $(PWD)/../include
CFLAGS = "$(INCLUDES) -D DEBUG -Wall"
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD:= $(shell pwd)

.phony: all clean

all:
	make -C $(KERNELDIR) EXTRA_CFLAGS=${CFLAGS} M=$(PWD) modules

install: all
	sudo rmmod ti_mfa || true
	sudo insmod ti-mfa.ko

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

compile_commands.json: $(GEN_COMPILE_COMMANDS)
	python3 $(GEN_COMPILE_COMMANDS) -O $(KERNELDIR) $(PWD)
	mv compile_commands.json ../../
