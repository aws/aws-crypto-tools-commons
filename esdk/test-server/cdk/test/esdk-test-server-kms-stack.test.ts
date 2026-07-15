import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { EsdkTestServerKmsStack } from '../lib/esdk-test-server-kms-stack';

// Task 15.2: CDK synth/snapshot assertions for the KMS_Test_Resources stack.
// This is a declarative-IaC verification (synthesized-template assertions), NOT
// a property test. Validates Requirements 14.5, 14.6, 14.12.

function synth(createOidcProvider = true): Template {
  const app = new cdk.App();
  const stack = new EsdkTestServerKmsStack(app, 'TestStack', {
    createOidcProvider,
    env: { account: '123456789012', region: 'us-west-2' },
  });
  return Template.fromStack(stack);
}

describe('EsdkTestServerKmsStack (createOidcProvider=true)', () => {
  const template = synth(true);

  test('provisions exactly three KMS keys', () => {
    template.resourceCountIs('AWS::KMS::Key', 3);
  });

  test('one key is multi-region (MRK)', () => {
    template.hasResourceProperties('AWS::KMS::Key', {
      MultiRegion: true,
    });
  });

  test('one key is an asymmetric RSA key', () => {
    template.hasResourceProperties('AWS::KMS::Key', {
      KeySpec: 'RSA_4096',
      KeyUsage: 'ENCRYPT_DECRYPT',
    });
  });

  test('one key is symmetric (SYMMETRIC_DEFAULT, not multi-region)', () => {
    template.hasResourceProperties('AWS::KMS::Key', {
      KeySpec: 'SYMMETRIC_DEFAULT',
      KeyUsage: 'ENCRYPT_DECRYPT',
      MultiRegion: Match.absent(),
    });
  });

  test('provisions the three stable aliases', () => {
    template.resourceCountIs('AWS::KMS::Alias', 3);
    for (const aliasName of [
      'alias/esdk-test-server/symmetric',
      'alias/esdk-test-server/mrk',
      'alias/esdk-test-server/rsa',
    ]) {
      template.hasResourceProperties('AWS::KMS::Alias', { AliasName: aliasName });
    }
  });

  test('creates a GitHub OIDC provider', () => {
    template.resourceCountIs('Custom::AWSCDKOpenIdConnectProvider', 1);
    template.hasResourceProperties('Custom::AWSCDKOpenIdConnectProvider', {
      Url: 'https://token.actions.githubusercontent.com',
      ClientIDList: ['sts.amazonaws.com'],
    });
  });

  test('creates an IAM role trusting only the two ESDK repos via OIDC', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'sts:AssumeRoleWithWebIdentity',
            Condition: {
              StringEquals: {
                'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
              },
              StringLike: {
                'token.actions.githubusercontent.com:sub': [
                  'repo:aws/aws-crypto-tools-commons:*',
                  'repo:aws/aws-crypto-tools-java:*',
                ],
              },
            },
          }),
        ]),
      },
    });
  });

  test('role policy grants least-privilege KMS actions scoped to key ARNs, not "*"', () => {
    // Core KMS actions on the three keys.
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: Match.arrayWith([
              'kms:Encrypt',
              'kms:Decrypt',
              'kms:GenerateDataKey',
              'kms:DescribeKey',
            ]),
            // Scoped to specific key ARN references, never the wildcard "*".
            Resource: Match.not('*'),
          }),
          // GetPublicKey for the RSA key.
          Match.objectLike({
            Effect: 'Allow',
            Action: 'kms:GetPublicKey',
            Resource: Match.not('*'),
          }),
        ]),
      },
    });
  });

  test('emits the documented CfnOutputs', () => {
    const outputs = template.findOutputs('*');
    for (const name of ['symmetricKeyArn', 'mrkArn', 'rsaKeyArn', 'roleArn']) {
      expect(outputs).toHaveProperty(name);
    }
  });
});

describe('EsdkTestServerKmsStack (createOidcProvider=false)', () => {
  const template = synth(false);

  test('does not create an OIDC provider but still creates the role', () => {
    template.resourceCountIs('Custom::AWSCDKOpenIdConnectProvider', 0);
    template.resourceCountIs('AWS::IAM::Role', 1);
  });

  test('still provisions the three KMS keys', () => {
    template.resourceCountIs('AWS::KMS::Key', 3);
  });
});
