#!/bin/bash

set -e
bucket=nik-stm32-ml-sources-old
#bucket=mlstage-mlstack-sagemakerpipelinemloutput3d9df56c-mjj60ydt8gph
mlpath=ml/tmp/ml

wsdir=.
#wsdir=/tmp/t
#mkdir -p /tmp/t
function s3sync {
  aws s3 sync --no-progress ${@}
}
s3sync s3://${bucket}/${mlpath}/stm32ai_files/Inc ${wsdir}/Middleware/STM32_AI_Library/Inc
s3sync s3://${bucket}/${mlpath}/stm32ai_files/Lib/ ${wsdir}/Middleware/STM32_AI_Library/Lib/
mv ${wsdir}/Middleware/STM32_AI_Library/Lib/NetworkRuntime730_CM33_GCC.a ${wsdir}/Middleware/STM32_AI_Library/Lib/NetworkRuntime800_CM33_GCC.a
s3sync s3://${bucket}/${mlpath}/C_header ${wsdir}/Projects/Common/dpu/
aws s3 cp --no-progress --recursive --exclude '*' --include 'network*' \
  s3://${bucket}/${mlpath}/stm32ai_files/ ${wsdir}/Projects/Common/X-CUBE-AI/App/
