.phony: all clean acceptance-tests

all:
	$(MAKE) -C src/kernel && $(MAKE) -C src/ti-mfa-conf

clean:
	$(MAKE) -C src clean

box:
	cd infrastructure
	vagrant --no-tty up
	vagrant --no-tty package --output debian_frr_linux_5.16.box
	vagrant --no-tty box add --force debian_frr_linux_5.16 debian_frr_linux_5.16.box
	popd

acceptance-tests:
	cd tests/testbed_2
	vagrant --no-tty up
	ansible-playbook --ssh-extra-args '-o StrictHostKeyChecking=no' -i .vagrant/provisioners/ansible/inventory/vagrant_ansible_inventory acceptance-test.yml
	# vagrant --no-tty destroy -f
	cd ../../
