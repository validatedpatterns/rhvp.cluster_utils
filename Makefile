.PHONY: ansible-lint
ansible-lint: ## run ansible lint on ansible/ folder
	podman run -it -v $(PWD):/workspace:rw,z --workdir /workspace \
		--entrypoint "/usr/local/bin/ansible-lint" quay.io/ansible/creator-ee:latest  "-vvv" "roles" "plugins" "playbooks"

.PHONY: ansible-sanitytest
ansible-sanitytest: ## run ansible unit tests
	ansible-test sanity --docker default

.PHONY: ansible-unittest
ansible-unittest: ## run ansible unit tests
	rm -rf tests/output
	ansible-test units --docker

.PHONY: test
test: ansible-sanitytest ansible-unittest
