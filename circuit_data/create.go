package circuitdata

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// get CS from bytes
func GetNewCSFromBytes(csBytes []byte) (constraint.ConstraintSystem, error) {
	csBuf := *bytes.NewBuffer(csBytes)
	cs := groth16.NewCS(ecc.BN254)
	_, err := cs.ReadFrom(&csBuf)
	if err != nil {
		return cs, err
	}
	return cs, nil
}

// get PK from bytes
func GetNewPKFromBytes(pkBytes []byte) (groth16.ProvingKey, error) {
	pkBuf := *bytes.NewBuffer(pkBytes)
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err := pk.ReadFrom(&pkBuf)
	if err != nil {
		return pk, err
	}
	return pk, nil
}
