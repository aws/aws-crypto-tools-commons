import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';

/**
 * Props for {@link EsdkTestServerKmsStack}.
 */
export interface EsdkTestServerKmsStackProps extends cdk.StackProps {
  /**
   * Whether to create the GitHub OIDC provider in this account.
   *
   * An AWS account may only have one OIDC provider per URL
   * (token.actions.githubusercontent.com). If one already exists, set this to
   * `false` (via `-c createOidcProvider=false`) so the stack looks up the
   * existing provider by its well-known ARN instead of creating a conflicting
   * one. Defaults to `true`.
   */
  readonly createOidcProvider?: boolean;
}

/**
 * Provisions the ESDK TestServer KMS_Test_Resources as infrastructure-as-code
 * (Requirement 14.5, 14.6):
 *
 *   - a symmetric KMS key       (SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT) -> AwsKms
 *   - a multi-region KMS key    (MRK)                                -> AwsKmsMrk
 *   - a SECOND multi-region KMS key (MRK)                            -> AwsKmsMrkMultiKeyring
 *   - an asymmetric RSA KMS key (RSA_4096, ENCRYPT_DECRYPT)          -> AwsKmsRsa
 *
 * The two multi-region keys back the AwsKmsMrkMultiKeyring round-trip: the
 * first MRK is the generator and the second MRK is a child key, so the
 * MRK-aware multi-keyring is exercised over genuinely distinct MRKs rather
 * than a single key.
 *
 * plus a GitHub OIDC provider and an IAM role the CI workflows assume via OIDC
 * (Requirement 14.11), whose trust policy is restricted to the two ESDK repos
 * and whose permissions are least-privilege KMS actions scoped to exactly the
 * keys above (Requirement 14.12).
 *
 * The stack is account-agnostic (no hardcoded account) and defaults its region
 * to us-west-2 (set by the app entry point). It is verified by CDK synth /
 * assertion tests, not property tests — it is declarative IaC.
 */
export class EsdkTestServerKmsStack extends cdk.Stack {
  /** GitHub Actions OIDC issuer host. */
  private static readonly GITHUB_OIDC_URL = 'token.actions.githubusercontent.com';
  /** Audience presented by aws-actions/configure-aws-credentials. */
  private static readonly GITHUB_OIDC_AUDIENCE = 'sts.amazonaws.com';
  /** Repositories whose GitHub Actions workflows may assume the CI role. */
  private static readonly TRUSTED_REPOS = [
    'aws/aws-crypto-tools-commons',
    'aws/aws-crypto-tools-java',
  ];

  constructor(scope: Construct, id: string, props: EsdkTestServerKmsStackProps = {}) {
    super(scope, id, props);

    const createOidcProvider = props.createOidcProvider ?? true;

    // Test keys: destroy on stack deletion with the shortest allowed pending
    // window (7 days) so teardown is not blocked. These are disposable test
    // resources, not production keys. Nothing here enables deletion protection.
    const removalPolicy = cdk.RemovalPolicy.DESTROY;
    const pendingWindow = cdk.Duration.days(7);

    // --- Symmetric key (backs AwsKms, AwsKmsMultiKeyring, AwsKmsDiscovery) ---
    const symmetricKey = new kms.Key(this, 'SymmetricKey', {
      description: 'ESDK TestServer symmetric KMS key (AwsKms / multi / discovery)',
      keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
      alias: 'alias/esdk-test-server/symmetric',
      removalPolicy,
      pendingWindow,
    });

    // --- Multi-region key (backs AwsKmsMrk) ---
    // The L2 kms.Key construct does not expose `multiRegion`, so the MRK is
    // created with the L1 CfnKey. It carries the standard default key policy
    // (root account admin) so that IAM-policy-based grants — like the CI role's
    // least-privilege statements below — are honored.
    const mrkCfn = new kms.CfnKey(this, 'MultiRegionKey', {
      description: 'ESDK TestServer multi-region KMS key (AwsKmsMrk)',
      multiRegion: true,
      keySpec: 'SYMMETRIC_DEFAULT',
      keyUsage: 'ENCRYPT_DECRYPT',
      pendingWindowInDays: pendingWindow.toDays(),
      keyPolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'EnableIAMPolicies',
            Effect: 'Allow',
            Principal: { AWS: `arn:${this.partition}:iam::${this.account}:root` },
            Action: 'kms:*',
            Resource: '*',
          },
        ],
      },
    });
    mrkCfn.applyRemovalPolicy(removalPolicy);
    // Import as an IKey so aliases/ARNs read consistently with the L2 keys.
    const mrk = kms.Key.fromKeyArn(this, 'MultiRegionKeyRef', mrkCfn.attrArn);
    new kms.CfnAlias(this, 'MultiRegionKeyAlias', {
      aliasName: 'alias/esdk-test-server/mrk',
      targetKeyId: mrkCfn.attrKeyId,
    });

    // --- Second multi-region key (backs AwsKmsMrkMultiKeyring as a child key) ---
    // A distinct MRK so the AwsKmsMrkMultiKeyring round-trip spans two genuinely
    // different multi-region keys (generator = first MRK, child = this one),
    // rather than degenerating to a single key. Created with the same L1 CfnKey
    // pattern and default key policy as the first MRK.
    const mrk2Cfn = new kms.CfnKey(this, 'MultiRegionKey2', {
      description: 'ESDK TestServer second multi-region KMS key (AwsKmsMrkMultiKeyring child)',
      multiRegion: true,
      keySpec: 'SYMMETRIC_DEFAULT',
      keyUsage: 'ENCRYPT_DECRYPT',
      pendingWindowInDays: pendingWindow.toDays(),
      keyPolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'EnableIAMPolicies',
            Effect: 'Allow',
            Principal: { AWS: `arn:${this.partition}:iam::${this.account}:root` },
            Action: 'kms:*',
            Resource: '*',
          },
        ],
      },
    });
    mrk2Cfn.applyRemovalPolicy(removalPolicy);
    const mrk2 = kms.Key.fromKeyArn(this, 'MultiRegionKey2Ref', mrk2Cfn.attrArn);
    new kms.CfnAlias(this, 'MultiRegionKey2Alias', {
      aliasName: 'alias/esdk-test-server/mrk2',
      targetKeyId: mrk2Cfn.attrKeyId,
    });

    // --- Asymmetric RSA key (backs AwsKmsRsa) ---
    const rsaKey = new kms.Key(this, 'RsaKey', {
      description: 'ESDK TestServer asymmetric RSA KMS key (AwsKmsRsa)',
      keySpec: kms.KeySpec.RSA_4096,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
      alias: 'alias/esdk-test-server/rsa',
      removalPolicy,
      pendingWindow,
    });

    // --- GitHub OIDC provider (create or look up existing) ---
    const oidcProvider: iam.IOpenIdConnectProvider = createOidcProvider
      ? new iam.OpenIdConnectProvider(this, 'GithubOidcProvider', {
          url: `https://${EsdkTestServerKmsStack.GITHUB_OIDC_URL}`,
          clientIds: [EsdkTestServerKmsStack.GITHUB_OIDC_AUDIENCE],
        })
      : iam.OpenIdConnectProvider.fromOpenIdConnectProviderArn(
          this,
          'GithubOidcProvider',
          `arn:${this.partition}:iam::${this.account}:oidc-provider/${EsdkTestServerKmsStack.GITHUB_OIDC_URL}`,
        );

    // Trust policy: restrict to the two ESDK repos on any branch/ref
    // (repo:aws/aws-crypto-tools-commons:* and repo:aws/aws-crypto-tools-java:*),
    // and require the sts.amazonaws.com audience.
    const subs = EsdkTestServerKmsStack.TRUSTED_REPOS.map((repo) => `repo:${repo}:*`);
    const principal = new iam.OpenIdConnectPrincipal(oidcProvider, {
      StringEquals: {
        [`${EsdkTestServerKmsStack.GITHUB_OIDC_URL}:aud`]:
          EsdkTestServerKmsStack.GITHUB_OIDC_AUDIENCE,
      },
      StringLike: {
        [`${EsdkTestServerKmsStack.GITHUB_OIDC_URL}:sub`]: subs,
      },
    });

    const ciRole = new iam.Role(this, 'CiKmsRole', {
      roleName: 'esdk-test-server-ci-kms-role',
      description:
        'Role assumed via GitHub OIDC by the ESDK TestServer CI workflows; least-privilege KMS on the test keys.',
      assumedBy: principal,
      maxSessionDuration: cdk.Duration.hours(1),
    });

    const allKeyArns = [symmetricKey.keyArn, mrk.keyArn, mrk2.keyArn, rsaKey.keyArn];

    // Least-privilege KMS actions scoped to exactly the three test key ARNs
    // (not "*") — Requirement 14.12.
    ciRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'EsdkTestServerKmsCoreActions',
        effect: iam.Effect.ALLOW,
        actions: [
          'kms:Encrypt',
          'kms:Decrypt',
          'kms:GenerateDataKey',
          'kms:GenerateDataKeyWithoutPlaintext',
          'kms:GenerateDataKeyPair',
          'kms:GenerateDataKeyPairWithoutPlaintext',
          'kms:DescribeKey',
        ],
        resources: allKeyArns,
      }),
    );

    // GetPublicKey is only needed to build the AwsKmsRsa keyring, scoped to the
    // RSA key alone.
    ciRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'EsdkTestServerKmsRsaGetPublicKey',
        effect: iam.Effect.ALLOW,
        actions: ['kms:GetPublicKey'],
        resources: [rsaKey.keyArn],
      }),
    );

    // --- Outputs (Requirement 14.6): stable, documented names ---
    new cdk.CfnOutput(this, 'symmetricKeyArn', {
      value: symmetricKey.keyArn,
      description: 'ARN of the symmetric KMS key (AwsKms). -> esdk.testserver.kms.symmetricKeyArn',
      exportName: 'EsdkTestServer-SymmetricKeyArn',
    });
    new cdk.CfnOutput(this, 'mrkArn', {
      value: mrk.keyArn,
      description: 'ARN of the multi-region KMS key (AwsKmsMrk). -> esdk.testserver.kms.mrkArn',
      exportName: 'EsdkTestServer-MrkArn',
    });
    new cdk.CfnOutput(this, 'mrkKeyId', {
      value: mrk.keyId,
      description: 'Key id of the multi-region KMS key (AwsKmsMrk).',
      exportName: 'EsdkTestServer-MrkKeyId',
    });
    new cdk.CfnOutput(this, 'mrk2Arn', {
      value: mrk2.keyArn,
      description:
        'ARN of the second multi-region KMS key (AwsKmsMrkMultiKeyring child). '
        + '-> esdk.testserver.kms.mrk2Arn',
      exportName: 'EsdkTestServer-Mrk2Arn',
    });
    new cdk.CfnOutput(this, 'mrk2KeyId', {
      value: mrk2.keyId,
      description: 'Key id of the second multi-region KMS key (AwsKmsMrkMultiKeyring child).',
      exportName: 'EsdkTestServer-Mrk2KeyId',
    });
    new cdk.CfnOutput(this, 'rsaKeyArn', {
      value: rsaKey.keyArn,
      description: 'ARN of the asymmetric RSA KMS key (AwsKmsRsa). -> esdk.testserver.kms.rsaKeyArn',
      exportName: 'EsdkTestServer-RsaKeyArn',
    });
    new cdk.CfnOutput(this, 'roleArn', {
      value: ciRole.roleArn,
      description: 'ARN of the CI role to assume via GitHub OIDC (role-to-assume in CI).',
      exportName: 'EsdkTestServer-CiRoleArn',
    });
  }
}
