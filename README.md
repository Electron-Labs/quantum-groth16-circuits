# quantum-gnark-circuits

This is a Monorepo containing:

-   <u>aggregator</u>: Aggregation circuits
-   <u>indexed_merkle_tree</u>: Indexed Merkle Tree circuits used for aggregation
-   <u>quantum_reduction_circuits</u>: groth16 verifier circuits

### setup

Make sure you have go installed in your system. ([guide here](https://go.dev/doc/install))

-   `go mod tidy`

### test

-   #### quantum_reduction_circuits
    -   `go test -run ^TestVerifier$ github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16 -test.v -tags=debug`
    -   `go test -run ^TestVerifier$ github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/circom_groth16 -test.v -tags=debug`
-   #### indexed_merkle_tree
    -   `go test github.com/Electron-Labs/quantum-gnark-circuits/indexed_merkle_tree/circuit_test.go -test.v -tags=debug`

### benchmarks

These benchmarks are corresponding are `BATCH_SIZE=8` and `TREE_DEPTH=9`.

| Machine          | Proving time (sec) |
| ---------------- | ------------------ |
| AWS r6a.32xlarge | ~98                |
| AWS r6a.16xlarge | ~128               |
| AWS r6a.8xlarge  | ~172               |

To reproduce the benchmarks, run:

-   `./scripts/run_e2e.sh`
