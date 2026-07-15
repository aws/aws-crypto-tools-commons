# ============================================================================
# ESDK TestServer — developer convenience Makefile
# ----------------------------------------------------------------------------
# The ESDK TestServer is split into FOUR INDEPENDENT Gradle builds (not a
# composite build), each with its own wrapper:
#
#   model/         the single Smithy model (validated with the smithy CLI)
#   client-java/   the generated Java Test_Client   (root: esdk-test-server-client-java)
#   servers/java/  the Java Language_Server         (root: esdk-test-server-java)
#   tests/         the single Java Tests suite       (root: esdk-test-server-tests)
#
# Because they are separate builds, you cannot (for example) run the server's
# `runServer` task from the tests module. This Makefile hides that by cd-ing
# into the correct module for each target.
#
# Usage examples:
#   make                       # show help (default goal)
#   make validate              # smithy validate + model smoke checks
#   make build                 # fast compile/codegen check of all modules
#   make test                  # in-process round trip (recommended green path)
#   make run-server PORT=9090  # start the Java server in the foreground
#   make test-live PORT=9091   # orchestrated over-HTTP round trip
#   make JAVA_HOME=/path/to/jdk21 test   # force a specific JDK
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
SERVER_DIR := $(MAKEFILE_DIR)/servers/java
TESTS_DIR  := $(MAKEFILE_DIR)/tests
ORCH_DIR   := $(MAKEFILE_DIR)/orchestrator
CDK_DIR    := $(MAKEFILE_DIR)/cdk

# ----------------------------------------------------------------------------
# KMS_Test_Resources coordinates for the ONLINE, credential-gated KMS Tests
# (task 15.8). These are read from the environment so a developer can export
# them once (from the CDK stack's CfnOutputs) and run `make test-kms`. The
# region defaults to us-west-2. They map 1:1 to the runtime-config keys the
# Tests read (esdk.testserver.kms.*) via KmsRuntimeConfig.
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

# Makefile-owned scratch directory for temp files (server log for test-live).
# Kept separate from the per-module Gradle `build/` dirs to avoid confusion,
# and ignored via the sibling .gitignore.
TMP_DIR    := $(MAKEFILE_DIR)/.make-tmp
SERVER_LOG := $(TMP_DIR)/roundtrip-server.log

# Port used by run-server / test-live (override on the command line, e.g.
# `make run-server PORT=9090`). Defaults to 9090.
PORT ?= 9090

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

.PHONY: help check-java validate smoke build build-client build-server build-tests \
        test run-server test-live roundtrip orchestrate orchestrate-test \
        deploy-kms-cdk test-kms clean

# ----------------------------------------------------------------------------
help: ## Show this help
	@echo "ESDK TestServer — make targets"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_ -]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-20s %s\n", $$1, $$2}'
	@echo ""
	@echo "Variables:"
	@echo "  PORT=$(PORT)         port for run-server / test-live"
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
validate: ## Validate the Smithy model (smithy validate + model smoke checks)
	@echo "==> smithy validate (model/)"
	@cd "$(MODEL_DIR)" && smithy validate
	@echo "==> model structural smoke check"
	@bash "$(MODEL_DIR)/tests/structural_smoke_check.sh"
	@echo "==> model reject-polymorph check"
	@bash "$(MODEL_DIR)/tests/reject_polymorph_check.sh"

# ----------------------------------------------------------------------------
smoke: ## Run model smoke checks and the tests round-trip smoke check
	@echo "==> model structural smoke check"
	@bash "$(MODEL_DIR)/tests/structural_smoke_check.sh"
	@echo "==> model reject-polymorph check"
	@bash "$(MODEL_DIR)/tests/reject_polymorph_check.sh"
	@echo "==> tests round-trip smoke check"
	@bash "$(TESTS_DIR)/smoke/round_trip_smoke_check.sh"

# ----------------------------------------------------------------------------
build: build-client build-server build-tests ## Build all modules (skips tests: fast compile/codegen check)
	@echo "==> All modules built (tests skipped)."

build-client: check-java ## Build the Java Test_Client (client-java, skips tests)
	@echo "==> Building client-java"
	@cd "$(CLIENT_DIR)" && ./gradlew build -x test

build-server: check-java ## Build the Java Language_Server (servers/java, skips tests)
	@echo "==> Building servers/java"
	@cd "$(SERVER_DIR)" && ./gradlew build -x test

build-tests: check-java ## Build the Tests suite (tests, skips tests)
	@echo "==> Building tests"
	@cd "$(TESTS_DIR)" && ./gradlew build -x test

# ----------------------------------------------------------------------------
test: check-java ## Run the Tests (boots the server in-process). KMS scenarios are REQUIRED: needs AWS creds
	@echo "==> Running in-process round trip (tests/)"
	@echo "    NOTE: the KMS keyring scenarios are required and run against the default"
	@echo "    KMS_Test_Resources, so valid AWS credentials must be present (e.g. run \`creds\`)."
	@echo "    Override the default key ARNs with ESDK_TESTSERVER_KMS_* (see test-kms)."
	@cd "$(TESTS_DIR)" && ./gradlew test

# ----------------------------------------------------------------------------
run-server: check-java ## Start the Java server in the FOREGROUND on PORT (blocks; Ctrl-C to stop)
	@echo "==> Starting Java Language_Server on port $(PORT) (foreground; Ctrl-C to stop)"
	@cd "$(SERVER_DIR)" && ./gradlew runServer --args="$(PORT)"

# ----------------------------------------------------------------------------
# Orchestrated over-HTTP round trip. Because macOS make (3.81) runs each recipe
# line in its own shell, the whole orchestration is one script exported via the
# environment and executed in a single `bash -c` so the PID, cleanup function
# and trap all share one shell. It starts the server in the BACKGROUND, waits
# until it accepts connections (with a timeout), runs the Tests against it, and
# ALWAYS stops the server (even on failure), propagating the Tests' exit code.
define RUN_LIVE
set -eo pipefail
mkdir -p "$(TMP_DIR)"
echo "==> test-live: PORT=$(PORT)"
echo "    server log: $(SERVER_LOG)"

# Start the server in the background; capture the launcher PID.
( cd "$(SERVER_DIR)" && exec ./gradlew --console=plain -q runServer --args="$(PORT)" ) >"$(SERVER_LOG)" 2>&1 &
SERVER_PID=$$!

# Cleanup runs on ANY exit (success, test failure, timeout, Ctrl-C): kill the
# launcher subtree AND anything still bound to the port, so we never leave an
# orphaned server process behind.
cleanup() {
	trap - EXIT INT TERM
	echo "==> Stopping background server (pid $$SERVER_PID) and freeing port $(PORT)"
	pkill -P "$$SERVER_PID" 2>/dev/null || true
	kill "$$SERVER_PID" 2>/dev/null || true
	pids=$$(lsof -ti tcp:$(PORT) 2>/dev/null || true)
	if [ -n "$$pids" ]; then kill $$pids 2>/dev/null || true; fi
	sleep 1
	pids=$$(lsof -ti tcp:$(PORT) 2>/dev/null || true)
	if [ -n "$$pids" ]; then kill -9 $$pids 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# Wait until the server accepts connections (or the log confirms it), failing
# fast if the process dies or we exceed the timeout.
echo "==> Waiting for server to accept connections on 127.0.0.1:$(PORT)"
attempts=0
max_attempts=180
until nc -z 127.0.0.1 "$(PORT)" >/dev/null 2>&1 || grep -q "listening at http://127.0.0.1:$(PORT)" "$(SERVER_LOG)" 2>/dev/null; do
	if ! kill -0 "$$SERVER_PID" 2>/dev/null && ! lsof -ti tcp:$(PORT) >/dev/null 2>&1; then
		echo "ERROR: server process exited before becoming ready. Last log lines:" >&2
		tail -n 40 "$(SERVER_LOG)" >&2 || true
		exit 1
	fi
	attempts=$$((attempts + 1))
	if [ "$$attempts" -ge "$$max_attempts" ]; then
		echo "ERROR: timed out after $${max_attempts}s waiting for the server. Last log lines:" >&2
		tail -n 40 "$(SERVER_LOG)" >&2 || true
		exit 1
	fi
	sleep 1
done
echo "==> Server is up. Running Tests against http://127.0.0.1:$(PORT)"

# Run the Tests against the external endpoint; capture the exit code so the EXIT
# trap can clean up before we propagate it.
set +e
( cd "$(TESTS_DIR)" && ./gradlew --console=plain test -Desdk.testserver.endpoints=http://127.0.0.1:$(PORT) )
rc=$$?
set -e
echo "==> Tests exit code: $$rc"
exit $$rc
endef
export RUN_LIVE

test-live roundtrip: check-java ## Start server in background on PORT, run Tests over HTTP, then always stop it
	@bash -c "$$RUN_LIVE"

# ----------------------------------------------------------------------------
orchestrate: check-java ## Run the orchestrator end-to-end (launch Java server on its configured port, run Tests, fail-open Result)
	@echo "==> Running the ESDKTestServer orchestrator (orchestrator/)"
	@cd "$(ORCH_DIR)" && ./gradlew --console=plain run

orchestrate-test: check-java ## Run the orchestrator's property + integration tests (Properties 11-14, port binding/conflict, error paths)
	@echo "==> Running orchestrator tests (orchestrator/)"
	@cd "$(ORCH_DIR)" && ./gradlew --console=plain test

# ----------------------------------------------------------------------------
# ONLINE AWS KMS keyring coverage (task 15) — REQUIRED.
# ----------------------------------------------------------------------------
# The KMS keyring scenarios (AwsKms / AwsKmsMrk / AwsKmsMultiKeyring / AwsKmsRsa
# / AwsKmsDiscovery) are ONLINE: they make real AWS KMS calls on encrypt/decrypt.
# They are REQUIRED and ALWAYS run against the KMS_Test_Resources, whose ARNs
# default in KmsRuntimeConfig — so `make test` / `make orchestrate` need valid
# AWS credentials (e.g. run `creds`) and a run does NOT pass unless the KMS
# scenarios run and pass. `test-kms` below is a convenience for pointing the
# Tests at a DIFFERENT set of keys by exporting the ESDK_TESTSERVER_KMS_* ARNs;
# for the default keys, plain `make test` already includes the KMS scenarios.
#
# Local flow to run the KMS Tests against a non-default key set:
#   1. Obtain developer AWS credentials for the CI resources account (Amazon:
#      run `creds` / `ada credentials update ...` / `aws sso login` — whatever
#      your environment uses so `aws sts get-caller-identity` succeeds).
#   2. `make deploy-kms-cdk`  (once) to provision the keys; note the CfnOutputs.
#   3. export the three key ARNs (and optionally the region) into your env.
#   4. `make test-kms`        to run the Tests WITH the KMS scenarios included.

deploy-kms-cdk: ## Deploy the KMS_Test_Resources CDK stack (needs AWS creds via `creds`); prints key/role ARNs
	@echo "==> Deploying EsdkTestServerKmsStack from cdk/ (region $(ESDK_TESTSERVER_KMS_REGION))"
	@echo "    Requires developer AWS credentials for the target account."
	@echo "    Obtain them first (e.g. run \`creds\`) so \`aws sts get-caller-identity\` works."
	@echo "    createOidcProvider=$(CREATE_OIDC_PROVIDER) (import existing GitHub OIDC provider unless =true)."
	@echo "    On success, CDK prints the CfnOutputs: symmetricKeyArn, mrkArn, rsaKeyArn, roleArn."
	@echo "    Export them for \`make test-kms\`:"
	@echo "      export ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN=<symmetricKeyArn>"
	@echo "      export ESDK_TESTSERVER_KMS_MRK_ARN=<mrkArn>"
	@echo "      export ESDK_TESTSERVER_KMS_RSA_KEY_ARN=<rsaKeyArn>"
	@cd "$(CDK_DIR)" && npm install && \
		AWS_REGION="$(ESDK_TESTSERVER_KMS_REGION)" npx cdk deploy --require-approval never \
			-c createOidcProvider=$(CREATE_OIDC_PROVIDER)

test-kms: check-java ## Run the Tests INCLUDING online KMS scenarios (needs `creds` + exported KMS ARNs)
	@if [ -z "$${ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN:-}" ] || \
		[ -z "$${ESDK_TESTSERVER_KMS_MRK_ARN:-}" ] || \
		[ -z "$${ESDK_TESTSERVER_KMS_RSA_KEY_ARN:-}" ]; then \
		echo "ERROR: the KMS_Test_Resources ARNs are not set in the environment." >&2; \
		echo "       KMS Tests are ONLINE and are skipped without them (and without AWS creds)." >&2; \
		echo "       First obtain AWS credentials (e.g. run \`creds\`), then export:" >&2; \
		echo "         export ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN=<arn>" >&2; \
		echo "         export ESDK_TESTSERVER_KMS_MRK_ARN=<arn>" >&2; \
		echo "         export ESDK_TESTSERVER_KMS_RSA_KEY_ARN=<arn>" >&2; \
		echo "         export ESDK_TESTSERVER_KMS_REGION=$(ESDK_TESTSERVER_KMS_REGION)  # optional" >&2; \
		echo "       (Get the ARNs from \`make deploy-kms-cdk\`.) Then re-run \`make test-kms\`." >&2; \
		exit 1; \
	fi
	@echo "==> Running Tests WITH online KMS scenarios (region $${ESDK_TESTSERVER_KMS_REGION:-$(ESDK_TESTSERVER_KMS_REGION)})"
	@echo "    (real AWS KMS calls happen on encrypt/decrypt; requires valid AWS credentials.)"
	@cd "$(TESTS_DIR)" && ./gradlew test \
		-Desdk.testserver.kms.symmetricKeyArn="$$ESDK_TESTSERVER_KMS_SYMMETRIC_KEY_ARN" \
		-Desdk.testserver.kms.mrkArn="$$ESDK_TESTSERVER_KMS_MRK_ARN" \
		-Desdk.testserver.kms.rsaKeyArn="$$ESDK_TESTSERVER_KMS_RSA_KEY_ARN" \
		-Desdk.testserver.kms.region="$${ESDK_TESTSERVER_KMS_REGION:-$(ESDK_TESTSERVER_KMS_REGION)}"

# ----------------------------------------------------------------------------
clean: ## gradle clean in every module + remove Makefile temp files
	@echo "==> Cleaning client-java"
	@cd "$(CLIENT_DIR)" && ./gradlew clean || true
	@echo "==> Cleaning servers/java"
	@cd "$(SERVER_DIR)" && ./gradlew clean || true
	@echo "==> Cleaning tests"
	@cd "$(TESTS_DIR)" && ./gradlew clean || true
	@echo "==> Cleaning orchestrator"
	@cd "$(ORCH_DIR)" && ./gradlew clean || true
	@echo "==> Removing Makefile temp files ($(TMP_DIR))"
	@rm -rf "$(TMP_DIR)"
