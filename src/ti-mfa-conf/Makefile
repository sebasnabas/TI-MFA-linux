default:
	gcc ti_mfa_conf.c -Wall -o ti-mfa-conf

clean: deinstall
	rm ti-mfa-conf || true

install: default
	sudo cp -f ti-mfa-conf /usr/bin

deinstall:
	[ -f /usr/bin/ti-mfa-conf ] && sudo rm /usr/bin/ti-mfa-conf || true
