package verifier

type G1 struct {
	X string
	Y string
}

type G1A struct {
	A0 string
	A1 string
}

type G2 struct {
	X G1A
	Y G1A
}

type Proof struct {
	Ar            G1
	Krs           G1
	Bs            G2
	Commitments   []G1
	CommitmentPok G1
}

type G1Elms struct {
	Alpha G1
	Beta  G1
	Delta G1
	K     []G1
}

type G2Elms struct {
	Beta  G2
	Delta G2
	Gamma G2
}

type CommitmentKey struct {
	G             G2
	GRootSigmaNeg G2
}

type VK struct {
	G1                           G1Elms
	G2                           G2Elms
	CommitmentKey                CommitmentKey
	PublicAndCommitmentCommitted [][]int
}
