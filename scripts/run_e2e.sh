#!/usr/bin/env bash

set -e

OUTPUT_DIR=artifacts
BATCH_SIZE=8
TREE_DEPTH=9
PROOFS_FILE=artifacts/proofs.json
VKS_FILE=artifacts/vks.json
PIS_FILE=artifacts/pis.json

# artifacts present in this bucket are built for BATCH_SIZE=8 and TREE_DEPTH=9
wget https://quantum-benchmark-artifacts.s3.us-east-2.amazonaws.com/artifacts.tar.gz
tar -xzvf artifacts.tar.gz

go mod tidy

# uncomment the following lines to rebuild artifacts
# go run main.go --out $OUTPUT_DIR build reduction
# go run main.go --out $OUTPUT_DIR build imt --batchSize $BATCH_SIZE --treeDepth $TREE_DEPTH
# go run main.go --out $OUTPUT_DIR build agg --batchSize $BATCH_SIZE

go run main.go --out $OUTPUT_DIR prove e2e --proofs $PROOFS_FILE --vks $VKS_FILE --pis $PIS_FILE
