// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { Stack, StackProps, CfnOutput, aws_s3 } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Code } from './code';
import { Analytics } from './analytics';

export class IotStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const { firmwareBucket, thingNamePrefix, publicKey } = new Code(this, 'Code');
    new Analytics(this, 'Analytics');

    new CfnOutput(this, 'FirmwareBucket', {
      description: 'Firmware Bucket',
      value: firmwareBucket.bucketName,
    });
    new CfnOutput(this, 'ProvisionScript', {
      description: 'Provision device',
      value: `python tools/provision.py --interactive --thing-name ${thingNamePrefix}-<Replace_With_Unique_Name>`,
    });
    new CfnOutput(this, 'PublicKey', {
      description: 'Public key used for signing firmware',
      value: '\n' + publicKey,
    });
  }
}