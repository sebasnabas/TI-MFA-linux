.phony: all clean acceptance-tests

all:
	$(MAKE) -C src

clean:
	$(MAKE) -C src/ clean

acceptance-tests:
	cd tests/testbed_2
	vagrant --no-tty up
	ansible-playbook --ssh-extra-args '-o StrictHostKeyChecking=no' -i .vagrant/provisioners/ansible/inventory/vagrant_ansible_inventory acceptance-test.yml
	# vagrant --no-tty destroy -f
	cd ../../

