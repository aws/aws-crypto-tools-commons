# ESDK TestServer — KMS Test Resources (AWS CDK)

TypeScript AWS CDK v2 app that provisions the `KMS_Test_Resources` used by the
ESDK TestServer's online, credential-gated KMS keyring round-trip Tests
(Requirement 14), plus the GitHub OIDC role the CI workflows assume.

The single stack, `EsdkTestServerKmsStack`, provisions:

- a **symmetric** KMS key (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`) — backs `AwsKms`,
  and (combined with the others) `AwsKmsMultiKeyring` / `AwsKmsDiscovery`
  — alias `alias/esdk-test-server/symmetric`;
- a **multi-region** KMS key (MRK) — backs `AwsKmsMrk` — alias `alias/esdk-test-server/mrk`;
- an **asymmetric RSA** KMS key (`RSA_4096`, `ENCRYPT_DECRYPT`) — backs `AwsKmsRsa`
  — alias `alias/esdk-test-server/rsa`;
- a **GitHub OIDC provider** (`token.actions.githubusercontent.com`, audience
  `sts.amazonaws.com`) and an **IAM role** whose trust policy is restricted to the
  `aws/aws-crypto-tools-commons` and `aws/aws-crypto-tools-java` repos, with
  least-privilege KMS permissions (`kms:Encrypt`, `kms:Decrypt`,
  `kms:GenerateDataKey*`, `kms:DescribeKey` on all three keys, plus
  `kms:GetPublicKey` on the RSA key) scoped to exactly those three key ARNs.

The app is **account-agnostic** (no hardcoded account) and defaults its region to
**`us-west-2`**.

## Prerequisites

- Node.js 18+ and npm (tested with Node 20/23).
- AWS CDK v2 CLI: `npm i -g aws-cdk` (or use the local `npx cdk`).

## Install and synthesize (offline, no AWS credentials)

```bash
npm ci        # or: npm install (first time, to generate package-lock.json)
npx cdk synth # renders the CloudFormation template to cdk.out/ — no AWS calls
```

Run the assertion tests (also offline):

```bash
npm test
```

## Deploy (requires AWS credentials)

Deploy needs AWS credentials for the target CI-resources account. In this
repository's environment, obtain them with your usual `creds` helper first (that
helper is not available in the automated build environment — deploy is a manual
developer/CI step), then:

```bash
# one-time per account/region:
npx cdk bootstrap

npx cdk deploy
```

### Region override

The region defaults to `us-west-2`. Override with any of:

```bash
npx cdk deploy -c region=us-east-1
# or
AWS_REGION=us-east-1 npx cdk deploy
```

### OIDC provider flag (`-c createOidcProvider`)

By default the stack **creates** the GitHub OIDC provider
(`token.actions.githubusercontent.com`). An AWS account can only have one OIDC
provider per URL, so if one already exists in the target account, deploy with:

```bash
npx cdk deploy -c createOidcProvider=false
```

which makes the stack **look up** the existing provider (by its well-known ARN
`arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com`)
instead of creating a conflicting one. This is a read-only import — it does
**not** modify or delete the shared provider that other CI roles in the account
may already trust.

The `make deploy-kms-cdk` target **defaults to `createOidcProvider=false`**
(import the existing provider), since the CI-resources account already has a
GitHub OIDC provider. Deploying into a brand-new account with no provider yet?
Run it once with `make deploy-kms-cdk CREATE_OIDC_PROVIDER=true`.

> If a prior deploy left the stack in `ROLLBACK_COMPLETE` (e.g. the
> `EntityAlreadyExistsException` failure from trying to create a second OIDC
> provider), CloudFormation cannot update it — delete the failed stack first
> with `npx cdk destroy` (or `aws cloudformation delete-stack --stack-name
> EsdkTestServerKmsStack`), then re-run the deploy.

## Outputs

After `cdk deploy`, the stack emits these `CfnOutput`s (stable names):

| Output             | Meaning                                              | Fed to Tests as                          |
| ------------------ | ---------------------------------------------------- | ---------------------------------------- |
| `symmetricKeyArn`  | ARN of the symmetric KMS key (`AwsKms`)              | `esdk.testserver.kms.symmetricKeyArn`    |
| `mrkArn`           | ARN of the multi-region KMS key (`AwsKmsMrk`)        | `esdk.testserver.kms.mrkArn`             |
| `mrkKeyId`         | Key id of the multi-region KMS key                   | (convenience)                            |
| `rsaKeyArn`        | ARN of the asymmetric RSA KMS key (`AwsKmsRsa`)      | `esdk.testserver.kms.rsaKeyArn`          |
| `roleArn`          | ARN of the CI role to assume via GitHub OIDC         | CI `role-to-assume`                      |

The region passed to the Tests is `esdk.testserver.kms.region` (default `us-west-2`).

## Teardown

The three test keys use `RemovalPolicy.DESTROY` with the shortest allowed KMS
pending window (7 days); nothing enables deletion protection, so `npx cdk destroy`
schedules the keys for deletion and removes the role and (if created) the OIDC
provider without manual intervention.
