// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * "Meta" Tests: they verify the <strong>TestServer implementation itself</strong>
 * — the wire contract, the {@code Client_Registry}, and the modeled-error
 * plumbing — rather than the cross-language behavior of the ESDK.
 *
 * <p>Because they exercise the harness (not the ESDK), these Tests are
 * <em>not</em> parameterized over the pairwise matrix of
 * {@code (language, majorVersion)} targets: they run against a single server (the
 * primary target). Conformance Tests that validate ESDK behavior — the
 * round-trip and key-commitment Tests — live in the parent package and DO fan out
 * across the cross-language target matrix.
 */
package aws.cryptography.esdk.testserver.tests.meta;
