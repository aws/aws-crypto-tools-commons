# ============================================================================
# ESDK TestServer — developer convenience Makefile
# ----------------------------------------------------------------------------
# The ESDK TestServer is split into SEPARATE Gradle builds (not a composite
# build), each with its own wrapper:
#
#   model/         the single Smithy model (validated with the smithy CLI)
#   client-java/   the generated Java Test_Client   (root: esdk-test-server-client-java)
#   servers/python/ the Python Language_Server      (hand-implemented, no build)
#   tests/         the single Java Tests suite       (root: esdk-test-server-tests)
#   orchestrator/  the Orchestrator core            (root: esdk-test-server-orchestrator)
#
# The Java Language_Server is NOT hosted here: it lives in the
# aws-crypto-tools-java Language_Repository at esdk/test-server/server
# (Requirement 1.2), and the orchestrated run resolves it from the java
# entry's Server_Location in config/configuration-set.json (Requirement 1.5).
#
# THE SINGLE ORCHESTRATED ENTRY POINT
# -----------------------------------
# `make orchestrate` is the one invocation that performs the complete
# cross-language run (Requirement 2.7): it resolves every configured
# Language_Server's source, builds and launches each as a subprocess on its
# configured port, runs the single Tests suite over the full pairwise
# (encrypt, decrypt) matrix of the launched Targets, prints the
# Resolution_Record, reports one fail-open Result, and always tears the
# servers down. There is NO separate Makefile-driven cross-language path — the
# old `test` / `test-live` / `test-cross-language` targets are retired in
# favor of `make orchestrate`.
#
# Usage examples:
#   make                       # show help (default goal)
#   make validate              # smithy validate + model smoke checks
#   make build                 # fast compile/codegen check of all modules
#   make orchestrate           # the complete cross-language Commons_Run
#   make orchestrate-test      # the orchestrator's own property/integration tests
#   make setup-python          # prepare the Python server env (clone/venv/install)
#   make JAVA_HOME=/path/to/jdk21 orchestrate   # force a specific JDK
#
# NOTE: written to work with the GNU Make 3.81 that ships with macOS, which
# predates `.ONESHELL`/`.SHELLFLAGS`. Multi-step recipes therefore either live
# on a single continued line or are run as one script via `bash -c "$$VAR"`.
# ============================================================================

# Use bash for recipes (3.81 honors the SHELL variable).
SHELL := bash

# Absolute directory containing this Makefile (works with `make -C`).
MAKEFILE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Module directories.
MODEL_DIR  := $(MAKEFILE_DIR)/model
CLIENT_DIR := $(MAKEFILE_DIR)/client-java
TESTS_DIR  := $(MAKEFILE_DIR)/tests
ORCH_DIR   := $(MAKEFILE_DIR)/orchestrator
CDK_DIR    := $(MAKEFILE_DIR)/cdk

# ----------------------------------------------------------------------------
# KMS_Test_Resources coordinates for the ONLINE, credential-gated KMS Tests.
# ----------------------------------------------------------------------------
# The KMS keyring scenarios are REQUIRED and run INSIDE the orchestrated run
# (`make orchestrate`); they are not a separate target. The Tests read the key
# ARNs from KmsRuntimeConfig, which defaults them but honors the
# ESDK_TESTSERVER_KMS_* environment variables (and matching
# esdk.testserver.kms.* system properties). To run `make orchestrate` against a
# non-default key set, export these before invoking it:
#   ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN -> esdk.testserver.kms.symmetricKeyArn
#   ESDK_TESTSERVER_KMS_MRK_ARN           -> esdk.testserver.kms.mrkArn
#   ESDK_TESTSERVER_KMS_RSA_KEY_ARN       -> esdk.testserver.kms.rsaKeyArn
#   ESDK_TESTSERVER_KMS_REGION            -> esdk.testserver.kms.region
ESDK_TESTSERVER_KMS_REGION ?= us-west-2

# Whether `deploy-kms-cdk` should CREATE the GitHub OIDC provider or import the
# existing one. An AWS account may hold only one OIDC provider per URL
# (token.actions.githubusercontent.com); if one already exists, creating another
# fails with EntityAlreadyExistsException. Defaults to `false` so the stack looks
# up the pre-existing provider by ARN (non-destructive — it does NOT touch the
# shared provider). Set `CREATE_OIDC_PROVIDER=true` the FIRST time you deploy
# into a brand-new account that has no GitHub OIDC provider yet.
CREATE_OIDC_PROVIDER ?= false

# Makefile-owned scratch directory for temp files. Kept separate from the
# per-module Gradle `build/` dirs to avoid confusion, and ignored via the
# sibling .gitignore. (The orchestrated run keeps its own scratch under
# orchestrator/build/; this is only used by `clean`.)
TMP_DIR    := $(MAKEFILE_DIR)/.make-tmp

# ----------------------------------------------------------------------------
# Python Language_Server environment (setup-python / run-python-server).
# ----------------------------------------------------------------------------
# The Python Language_Server is hand-implemented and delegates to the real AWS
# Encryption SDK for Python, installed from a clone of its repository. Python
# needs no compile step, so `setup-python` just clones + creates a venv +
# installs the ESDK editable from the relative path. NOTE: the orchestrated run
# (`make orchestrate`) sets up its own isolated Python environment via the
# PythonLaunchPlan, so `setup-python` / `run-python-server` are standalone
# developer conveniences for exercising the Python server by hand.
PYTHON3        ?= python3
PY_SERVER_DIR  := $(MAKEFILE_DIR)/servers/python
PY_ESDK_REPO   ?= https://github.com/aws/aws-encryption-sdk-python
PY_ESDK_DIR    := $(PY_SERVER_DIR)/.deps/aws-encryption-sdk-python
PY_VENV        := $(PY_SERVER_DIR)/.venv
PY_PYTHON      := $(PY_VENV)/bin/python
# Port for the standalone `run-python-server` convenience target.
PYTHON_PORT    ?= 8091

# ----------------------------------------------------------------------------
# JDK resolution
# ----------------------------------------------------------------------------
# smithy-java 1.4.0 requires JDK 21+. The shell default here is often Corretto
# 17, which FAILS the build. Resolve a JDK 21+ and export JAVA_HOME for every
# Gradle invocation, with this precedence:
#   1. Honor a caller-provided JAVA_HOME (env var or `make JAVA_HOME=...`).
#      `?=` means the resolver below only runs when JAVA_HOME is unset.
#   2. Try macOS /usr/libexec/java_home for 23, then 22, then 21. NOTE: on some
#      machines `java_home -v 21` happily returns a *17* JDK, so each candidate
#      is VALIDATED by reading its real major version and requiring >= 21.
#   3. Fall back to the known Homebrew JDK 23 if present.
#   4. Otherwise leave JAVA_HOME empty; java-requiring targets error clearly.
# Robust when /usr/libexec/java_home is absent (non-macOS): those command
# substitutions simply yield empty strings and are skipped.
JAVA_HOME ?= $(shell for c in "$$(/usr/libexec/java_home -v 23 2>/dev/null)" "$$(/usr/libexec/java_home -v 22 2>/dev/null)" "$$(/usr/libexec/java_home -v 21 2>/dev/null)" "/opt/homebrew/Cellar/openjdk/23.0.2/libexec/openjdk.jdk/Contents/Home"; do if [ -n "$$c" ] && [ -x "$$c/bin/java" ]; then v=$$("$$c/bin/java" -version 2>&1 | head -1 | sed -E 's/.*version .?([0-9]+).*/\1/'); if [ -n "$$v" ] && [ "$$v" -ge 21 ] 2>/dev/null; then echo "$$c"; break; fi; fi; done)

# Only export JAVA_HOME when we actually have one, so we never clobber a
# working PATH-based JDK (e.g. for the smithy CLI) with an empty value.
ifneq ($(strip $(JAVA_HOME)),)
export JAVA_HOME
endif

.DEFAULT_GOAL := help

.PHONY: help check-java validate smoke build build-client build-tests \
        orchestrate orchestrate-test \
        deploy-kms-cdk setup-python run-python-server clean

# ----------------------------------------------------------------------------
help: ## Show this help
	@echo "ESDK TestServer — make targets"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_ -]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-20s %s\n", $$1, $$2}'
	@echo ""
	@echo "The single orchestrated entry point is 'make orchestrate' (the complete"
	@echo "cross-language Commons_Run). The KMS scenarios are REQUIRED and run inside"
	@echo "it, so valid AWS credentials must be present (e.g. run \`creds\`)."
	@echo ""
	@echo "Variables:"
	@echo "  JAVA_HOME=$(if $(strip $(JAVA_HOME)),$(JAVA_HOME),<unresolved — set to a JDK 21+>)"

# ----------------------------------------------------------------------------
check-java: ## Verify a JDK 21+ is resolved (used by Gradle targets)
	@if [ -z "$(strip $(JAVA_HOME))" ]; then \
		echo "ERROR: could not resolve a JDK 21+ (smithy-java requires 21+)." >&2; \
		echo "       Set one explicitly, e.g.:  make JAVA_HOME=/path/to/jdk21 <target>" >&2; \
		exit 1; \
	fi
	@echo "==> Using JAVA_HOME=$(JAVA_HOME)"
	@"$(JAVA_HOME)/bin/java" -version 2>&1 | sed 's/^/    /'

# ----------------------------------------------------------------------------
validate: ## Validate the Smithy model + structural smoke checks (model + factoring)
	@echo "==> smithy validate (model/)"
	@cd "$(MODEL_DIR)" && smithy validate
	@echo "==> model structural smoke check"
	@bash "$(MODEL_DIR)/tests/structural_smoke_check.sh"
	@echo "==> model reject-polymorph check"
	@bash "$(MODEL_DIR)/tests/reject_polymorph_check.sh"
	@echo "==> factoring structural smoke check (config/tests/)"
	@bash "$(MAKEFILE_DIR)/config/tests/structural_smoke_check.sh"

# ----------------------------------------------------------------------------
smoke: ## Run model smoke checks and the tests round-trip smoke check
	@echo "==> model structural smoke check"
	@bash "$(MODEL_DIR)/tests/structural_smoke_check.sh"
	@echo "==> model reject-polymorph check"
	@bash "$(MODEL_DIR)/tests/reject_polymorph_check.sh"
	@echo "==> tests round-trip smoke check"
	@bash "$(TESTS_DIR)/smoke/round_trip_smoke_check.sh"

# ----------------------------------------------------------------------------
build: build-client build-tests ## Build all modules (skips tests: fast compile/codegen check)
	@echo "==> All modules built (tests skipped)."

build-client: check-java ## Build the Java Test_Client (client-java, skips tests)
	@echo "==> Building client-java"
	@cd "$(CLIENT_DIR)" && ./gradlew build -x test

build-tests: check-java ## Build the Tests suite (tests, skips tests)
	@echo "==> Building tests"
	@cd "$(TESTS_DIR)" && ./gradlew build -x test

# ----------------------------------------------------------------------------
# The single orchestrated entry point (Requirement 2.7). One invocation runs
# the complete cross-language Commons_Run: resolve + build + launch every
# configured Language_Server as a subprocess on its configured port, run the
# single Tests suite over the full pairwise matrix of the launched Targets,
# print the Resolution_Record, report one fail-open Result, and always tear the
# servers down. The KMS scenarios are REQUIRED, so valid AWS credentials must be
# present (e.g. run `creds`); export ESDK_TESTSERVER_KMS_* to point at a
# non-default key set.
orchestrate: check-java ## Run the complete cross-language Commons_Run (all servers, full matrix); needs AWS creds
	@echo "==> Running the ESDKTestServer orchestrator (orchestrator/) — complete cross-language run"
	@echo "    Launches every configured Language_Server on its port, runs the Tests over the"
	@echo "    full pairwise matrix, prints the Resolution_Record, and reports one fail-open Result."
	@echo "    The KMS keyring scenarios are REQUIRED: valid AWS credentials must be present"
	@echo "    (e.g. run \`creds\`); export ESDK_TESTSERVER_KMS_* to use a non-default key set."
	@cd "$(ORCH_DIR)" && ./gradlew --console=plain run

orchestrate-test: check-java ## Run the orchestrator's property + integration tests (pure pipeline logic, no AWS creds)
	@echo "==> Running orchestrator tests (orchestrator/)"
	@cd "$(ORCH_DIR)" && ./gradlew --console=plain test

# ----------------------------------------------------------------------------
# ONLINE AWS KMS keyring coverage — REQUIRED, run inside `make orchestrate`.
# ----------------------------------------------------------------------------
# The KMS keyring scenarios (AwsKms / AwsKmsMrk / AwsKmsMultiKeyring / AwsKmsRsa
# / AwsKmsDiscovery) are ONLINE: they make real AWS KMS calls on encrypt/decrypt.
# They are REQUIRED and run as part of the orchestrated cross-language run
# (`make orchestrate`) against the KMS_Test_Resources, whose ARNs default in
# KmsRuntimeConfig — so `make orchestrate` needs valid AWS credentials (e.g. run
# `creds`) and a run does NOT pass unless the KMS scenarios run and pass. To run
# against a DIFFERENT key set, export the ESDK_TESTSERVER_KMS_* variables (see
# the KMS_Test_Resources block above) before `make orchestrate`.
#
# Flow to provision and use a fresh key set:
#   1. Obtain developer AWS credentials for the CI resources account (Amazon:
#      run `creds` / `ada credentials update ...` / `aws sso login` — whatever
#      your environment uses so `aws sts get-caller-identity` succeeds).
#   2. `make deploy-kms-cdk`  (once) to provision the keys; note the CfnOutputs.
#   3. export the three key ARNs (and optionally the region) into your env.
#   4. `make orchestrate`     to run the full matrix WITH the KMS scenarios.

deploy-kms-cdk: ## Deploy the KMS_Test_Resources CDK stack (needs AWS creds via `creds`); prints key/role ARNs
	@echo "==> Deploying EsdkTestServerKmsStack from cdk/ (region $(ESDK_TESTSERVER_KMS_REGION))"
	@echo "    Requires developer AWS credentials for the target account."
	@echo "    Obtain them first (e.g. run \`creds\`) so \`aws sts get-caller-identity\` works."
	@echo "    createOidcProvider=$(CREATE_OIDC_PROVIDER) (import existing GitHub OIDC provider unless =true)."
	@echo "    On success, CDK prints the CfnOutputs: symmetricKeyArn, mrkArn, rsaKeyArn, roleArn."
	@echo "    Export them for \`make orchestrate\`:"
	@echo "      export ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN=<symmetricKeyArn>"
	@echo "      export ESDK_TESTSERVER_KMS_MRK_ARN=<mrkArn>"
	@echo "      export ESDK_TESTSERVER_KMS_RSA_KEY_ARN=<rsaKeyArn>"
	@cd "$(CDK_DIR)" && npm install && \
		AWS_REGION="$(ESDK_TESTSERVER_KMS_REGION)" npx cdk deploy --require-approval never \
			-c createOidcProvider=$(CREATE_OIDC_PROVIDER)

# ----------------------------------------------------------------------------
# Python Language_Server standalone conveniences. `setup-python` prepares the
# Python server's environment (clone the ESDK, create the venv, install); it is
# Python, so there is no compile step. These are for exercising the Python
# server by hand — the orchestrated run sets up its own isolated environment.
# ----------------------------------------------------------------------------
setup-python: ## Clone the Python ESDK, create the venv, and install the Python server deps
	@echo "==> Preparing the Python Language_Server environment"
	@if [ ! -d "$(PY_ESDK_DIR)/.git" ]; then \
		echo "==> Cloning $(PY_ESDK_REPO) -> $(PY_ESDK_DIR)"; \
		git clone --depth 1 "$(PY_ESDK_REPO)" "$(PY_ESDK_DIR)"; \
	else \
		echo "==> Python ESDK already cloned at $(PY_ESDK_DIR)"; \
	fi
	@if [ ! -x "$(PY_PYTHON)" ]; then \
		echo "==> Creating venv at $(PY_VENV)"; \
		"$(PYTHON3)" -m venv "$(PY_VENV)"; \
	fi
	@echo "==> Installing the Python ESDK (editable) + MPL + the server package"
	@"$(PY_VENV)/bin/pip" install --quiet --upgrade pip
	@"$(PY_VENV)/bin/pip" install --quiet \
		-e "$(PY_ESDK_DIR)" \
		'aws-cryptographic-material-providers>=1.7.4,<=1.11.2' \
		-e "$(PY_SERVER_DIR)"
	@echo "==> Python server environment ready ($(PY_PYTHON))"

run-python-server: ## Start the Python server in the FOREGROUND on PYTHON_PORT (needs setup-python first)
	@echo "==> Starting Python Language_Server on port $(PYTHON_PORT) (foreground; Ctrl-C to stop)"
	@cd "$(PY_SERVER_DIR)" && "$(PY_PYTHON)" -m esdk_test_server "$(PYTHON_PORT)"

# ----------------------------------------------------------------------------
clean: ## gradle clean in every module + remove Makefile temp files
	@echo "==> Cleaning client-java"
	@cd "$(CLIENT_DIR)" && ./gradlew clean || true
	@echo "==> Cleaning tests"
	@cd "$(TESTS_DIR)" && ./gradlew clean || true
	@echo "==> Cleaning orchestrator"
	@cd "$(ORCH_DIR)" && ./gradlew clean || true
	@echo "==> Removing Makefile temp files ($(TMP_DIR))"
	@rm -rf "$(TMP_DIR)"
