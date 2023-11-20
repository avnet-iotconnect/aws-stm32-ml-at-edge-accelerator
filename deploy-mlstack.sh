#!/bin/bash

set -e

npm run cdk deploy PipelineStack/MlStage/MlStack -- --require-approval never