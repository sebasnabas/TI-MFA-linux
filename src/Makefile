.phony: all clean

all: clean
	$(MAKE) -C ./kernel
	$(MAKE) -C ./ti-mfa-conf

install: kernel-install tool-install

clean:
	$(MAKE) -C ./kernel clean
	$(MAKE) -C ./ti-mfa-conf clean

kernel:
	$(MAKE) -C ./kernel

kernel-install:
	$(MAKE) -C ./kernel install

tool:
	$(MAKE) -C ./ti-mfa-conf

tool-install:
	$(MAKE) -C ./ti-mfa-conf install
