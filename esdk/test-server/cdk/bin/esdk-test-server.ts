#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { EsdkTestServerKmsStack } from '../lib/esdk-test-server-kms-stack';

const app = new cdk.App();

// Account-agnostic: no hardcoded account. The account is taken from the ambient
// credentials at deploy time (CDK_DEFAULT_ACCOUNT). Region defaults to us-west-2
// and is overridable via `-c region=<region>`, AWS_REGION, or CDK_DEFAULT_REGION.
const region =
  (app.node.tryGetContext('region') as string | undefined) ??
  process.env.CDK_DEFAULT_REGION ??
  process.env.AWS_REGION ??
  'us-west-2';

// Whether to create the GitHub OIDC provider (default true). If an OIDC provider
// for token.actions.githubusercontent.com already exists in the account, deploy
// with `-c createOidcProvider=false` to look up the existing provider instead of
// creating a conflicting one.
const createOidcProviderContext = app.node.tryGetContext('createOidcProvider');
const createOidcProvider =
  createOidcProviderContext === undefined
    ? true
    : createOidcProviderContext !== 'false' && createOidcProviderContext !== false;

new EsdkTestServerKmsStack(app, 'EsdkTestServerKmsStack', {
  createOidcProvider,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region,
  },
  description:
    'ESDK TestServer KMS_Test_Resources (symmetric, MRK, asymmetric RSA) and the GitHub OIDC CI role.',
});

app.synth();
