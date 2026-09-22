# ============================================================================
# MPL TestServer — developer convenience Makefile
# ----------------------------------------------------------------------------
# The MPL TestServer is split into SEPARATE Gradle builds (not a
# composite build), each with its own wrapper:
#
#   model/         the single Smithy model (validated with the smithy CLI)
#   client-java/   the generated Java Test_Client   (root: mpl-test-server-client-java)
#   tests/         the single Java Tests suite       (root: mpl-test-server-tests)
#
# The Orchestrator core lives in the shared ../../test-server-common/orchestrator/
# tree and runs against this SDK's data when invoked with
# `-Dtestserver.root=$(MAKEFILE_DIR)` (see `make orchestrate` below). Its
# runtime scratch — materialized clones, launch dirs, resolution record —
# lives under this Makefile's sibling `build/` directory, gitignored.
#
# The per-language Language_Servers are NOT hosted here: the Rust server lives
# in aws-crypto-tools-rust under mpl-test-server/, and the orchestrated run
# resolves each server from its entry's Server_Location in
# config/server-config.json.
#
# THE SINGLE ORCHESTRATED ENTRY POINT
# -----------------------------------
# `make orchestrate` is the one invocation that performs the complete
# cross-language run: it resolves every configured Language_Server's source,
# builds and launches each as a subprocess on its configured port, runs the
# single Tests suite over the full pairwise matrix of the launched Targets,
# prints the Resolution_Record, reports one fail-open Result, and always tears
# the servers down.
#
# Usage examples:
#   make                       # show help (default goal)
#   make validate              # smithy validate
#   make build                 # fast compile/codegen check of all modules
#   make orchestrate           # the complete cross-language Commons_Run
#   make orchestrate-test      # the orchestrator's own property/integration tests
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
ORCH_DIR   := $(abspath $(MAKEFILE_DIR)/../../test-server-common/orchestrator)

# ----------------------------------------------------------------------------
# Local aws-crypto-tools-rust checkout — the source of the Rust Language_Server
# (mpl-test-server/).
# ----------------------------------------------------------------------------
# `make orchestrate` passes this as a workingTreeOverlay (keyed by the repo
# name) to the orchestrator, so the Rust server component resolves to the local
# working tree instead of a git clone. Default: a sibling checkout,
# ../../../aws-crypto-tools-rust. Override with MPL_RUST_REPO=<abs path>
# when the checkout lives elsewhere.
MPL_RUST_REPO ?= $(abspath $(MAKEFILE_DIR)/../../../aws-crypto-tools-rust)

# The Rust working-tree overlay is applied ONLY when MPL_RUST_REPO
# actually exists (local development against a sibling checkout). In a
# Commons_Run CI there is no local Rust checkout, so the overlay is omitted and
# the server is resolved (git clone) from config/server-config.json's
# Server_Location.
RUST_OVERLAY := $(if $(wildcard $(MPL_RUST_REPO)),workingTreeOverlay.aws-crypto-tools-rust=$(MPL_RUST_REPO))

# Combined orchestrator program args. referenceImplementation=rust: the Rust
# server is the only configured language, so it plays the immaterial side of
# single-sided Tests (the orchestrator's default of java would abort as an
# unconfigured language). TESTS scopes the JUnit run when set.
ORCH_ARGS := $(strip referenceImplementation=rust $(RUST_OVERLAY) $(if $(strip $(TESTS)),tests=$(TESTS)))

# Makefile-owned scratch directory for temp files. Kept separate from the
# per-module Gradle `build/` dirs to avoid confusion, and ignored via the
# sibling .gitignore. (The orchestrated run keeps its own scratch under
# build/; this is only used by `clean`.)
TMP_DIR    := $(MAKEFILE_DIR)/.make-tmp

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

.PHONY: help check-java validate build build-client build-tests \
        orchestrate orchestrate-test clean

# ----------------------------------------------------------------------------
help: ## Show this help
	@echo "MPL TestServer — make targets"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_ -]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-20s %s\n", $$1, $$2}'
	@echo ""
	@echo "The single orchestrated entry point is 'make orchestrate' (the complete"
	@echo "cross-language Commons_Run)."
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
validate: ## Validate the Smithy model
	@echo "==> smithy validate (model/)"
	@cd "$(MODEL_DIR)" && smithy validate

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
# The single orchestrated entry point. One invocation runs the complete
# cross-language Commons_Run: resolve + build + launch every configured
# Language_Server as a subprocess on its configured port, run the single Tests
# suite over the full pairwise matrix of the launched Targets, print the
# Resolution_Record, report one fail-open Result, and always tear the servers
# down.
orchestrate: check-java ## Run the complete cross-language Commons_Run (all servers, full matrix)
	@echo "==> Running the TestServer orchestrator (test-server-common/orchestrator/, product=mpl) — complete cross-language run"
	@echo "    Launches every configured Language_Server on its port, runs the Tests over the"
	@echo "    full pairwise matrix, prints the Resolution_Record, and reports one fail-open Result."
	@# GRADLE_OPTS=-Dorg.gradle.daemon=false so no daemon captures a stale
	@# environment: every Gradle invocation — and every server/Tests JVM the
	@# orchestrator forks — inherits the live shell env.
	@#
	@# -Dtestserver.root=$(MAKEFILE_DIR) points the orchestrator at this SDK's
	@# config/tests tree (mpl/test-server/) instead of its own working
	@# directory; the runner's product-neutral commonsRootFrom logic picks up
	@# the mpl layout from there.
	@#
	@# workingTreeOverlay.aws-crypto-tools-rust lets the orchestrator use a
	@# sibling working tree directly for the Rust server component, so
	@# `make orchestrate` runs against uncommitted changes the same way it runs
	@# against a fully-committed one — no need to push a WIP commit just to
	@# feed the git-clone resolver.
	@#
	@# TESTS scopes the JUnit run to a single class or wildcard when set
	@# (e.g. `make orchestrate TESTS=RawAesRoundTripTest`). Empty runs every test.
	@cd "$(ORCH_DIR)" && GRADLE_OPTS="-Dorg.gradle.daemon=false $$GRADLE_OPTS" ./gradlew --console=plain run \
		-Dtestserver.root=$(MAKEFILE_DIR) \
		--args="$(ORCH_ARGS)"

orchestrate-test: check-java ## Run the orchestrator's property + integration tests (pure pipeline logic)
	@echo "==> Running orchestrator tests (test-server-common/orchestrator/)"
	@cd "$(ORCH_DIR)" && ./gradlew --console=plain test

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
