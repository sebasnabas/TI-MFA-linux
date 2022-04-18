all: kernel tool
install: kernel-install tool-install

kernel:
	$(MAKE) -C ./kernel

kernel-install:
	$(MAKE) -C ./kernel install

tool:
	$(MAKE) -C ./ti-mfa-conf

tool-install:
	$(MAKE) -C ./ti-mfa-conf
