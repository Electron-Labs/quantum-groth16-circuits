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

### benchmark

-   `./scripts/run_e2e.sh`
