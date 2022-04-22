default:
	gcc ti_mfa_conf.c -Wall -o ti-mfa-conf

clean: deinstall
	rm ti-mfa-conf || true

install:
	sudo cp -f ti-mfa-conf /usr/bin

deinstall:
	sudo rm /usr/bin/ti-mfa-conf || true
