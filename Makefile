##@ Common Tasks

.PHONY: help
help: ## This help message
	@echo "Pattern: $(NAME)"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^(\s|[a-zA-Z_0-9-])+:.*?##/ { printf "  \033[36m%-35s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: super-linter
super-linter: ## Runs super linter locally
	rm -rf .mypy_cache
	podman run -e RUN_LOCAL=true -e USE_FIND_ALGORITHM=true	\
					-e VALIDATE_ANSIBLE=false \
					-e VALIDATE_BASH=false \
					-e VALIDATE_CHECKOV=false \
					-e VALIDATE_DOCKERFILE_HADOLINT=false \
					-e VALIDATE_JSCPD=false \
					-e VALIDATE_JSON_PRETTIER=false \
					-e VALIDATE_MARKDOWN_PRETTIER=false \
					-e VALIDATE_KUBERNETES_KUBECONFORM=false \
					-e VALIDATE_PYTHON_PYLINT=false \
					-e VALIDATE_SHELL_SHFMT=false \
					-e VALIDATE_TEKTON=false \
					-e VALIDATE_YAML=false \
					-e VALIDATE_YAML_PRETTIER=false \
					$(DISABLE_LINTERS) \
					-v $(PWD):/tmp/lint:rw,z \
					-w /tmp/lint \
					ghcr.io/super-linter/super-linter:slim-v7

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
