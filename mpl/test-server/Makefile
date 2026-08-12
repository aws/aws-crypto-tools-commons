SHELL := bash

JAVA_HOME ?= $(shell /usr/libexec/java_home -v 21 2>/dev/null || echo $$JAVA_HOME)
export JAVA_HOME

.PHONY: help validate build build-client build-tests orchestrate clean

help: ## Show this help
	@echo "MPL TestServer — make targets"
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort | awk 'BEGIN{FS=":.*## "}{printf "  %-20s %s\n", $$1, $$2}'

validate: ## Validate the Smithy model
	cd model && smithy validate

build-client: ## Build the generated Java Test_Client
	cd client-java && ./gradlew build

build-tests: build-client ## Build the Tests suite
	cd tests && ./gradlew build

build: build-client build-tests ## Build client + tests
	cd orchestrator && ./gradlew build

orchestrate: ## Run the full orchestrated pipeline
	cd orchestrator && ./gradlew --console=plain run \
		--args="context=language:rust languageRepoRoot=$(LANGUAGE_REPO_ROOT)"

clean: ## Clean all build outputs
	cd client-java && ./gradlew clean || true
	cd tests && ./gradlew clean || true
	cd orchestrator && ./gradlew clean || true
