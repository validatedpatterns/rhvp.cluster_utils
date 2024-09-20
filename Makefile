##@ Common Tasks

.PHONY: help
help: ## This help message
	@echo "Pattern: $(NAME)"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^(\s|[a-zA-Z_0-9-])+:.*?##/ { printf "  \033[36m%-35s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

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
