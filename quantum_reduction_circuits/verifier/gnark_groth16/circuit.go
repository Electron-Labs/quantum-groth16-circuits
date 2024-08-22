package verifier

import (
	"fmt"

	circuitData "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

const MAX_PUB_INPUTS int = 20

type GnarkVerifier struct {
	Proof        stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	InnerWitness stdgroth16.Witness[sw_bn254.ScalarField]
	NumPubInputs frontend.Variable
	PubInputs    []frontend.Variable `gnark:",public"`
}

func (circuit *GnarkVerifier) Define(api frontend.API) error {
	if len(circuit.InnerWitness.Public) != MAX_PUB_INPUTS {
		return fmt.Errorf("wrong number of public inputs")
	}
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	pubInputsSerializedComputed, err := ComputePubInputs(api, circuit.VerifyingKey, circuit.InnerWitness.Public)
	if err != nil {
		return fmt.Errorf("ComputePubInputs: %w", err)
	}
	err = VerifyPublicInputs(api, pubInputsSerializedComputed, circuit.PubInputs)
	if err != nil {
		return fmt.Errorf("VerifyPublicInputs: %w", err)
	}
	baseField, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("NewField: %w", err)
	}
	for i := 0; i < MAX_PUB_INPUTS; i++ {
		gt := api.IsZero(api.Sub(1, api.Cmp(circuit.NumPubInputs, i)))
		pointAtInf := api.And(baseField.IsZero(&circuit.VerifyingKey.G1.K[i+1].X), baseField.IsZero(&circuit.VerifyingKey.G1.K[i+1].Y))
		api.AssertIsEqual(1, api.Xor(gt, pointAtInf))
	}
	return verifier.AssertProof(circuit.VerifyingKey, circuit.Proof, circuit.InnerWitness, stdgroth16.WithCompleteArithmetic())
}

func AppendBeInPlace(array *[]frontend.Variable, values []frontend.Variable) {
	*array = append(*array, Reverse(values)...)
}

func VKHash(api frontend.API, vk stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]) (vkHash circuitData.KeccakHash, err error) {
	var vkU64Elms []frontend.Variable

	// E
	AppendBeInPlace(&vkU64Elms, vk.E.C1.B2.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C1.B2.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C1.B1.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C1.B1.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C1.B0.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C1.B0.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C0.B2.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C0.B2.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C0.B1.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C0.B1.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C0.B0.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.E.C0.B0.A0.Limbs)

	// G1
	for i := 0; i < len(vk.G1.K); i++ {
		AppendBeInPlace(&vkU64Elms, vk.G1.K[i].X.Limbs)
		AppendBeInPlace(&vkU64Elms, vk.G1.K[i].Y.Limbs)
	}

	// G2
	AppendBeInPlace(&vkU64Elms, vk.G2.GammaNeg.P.X.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.GammaNeg.P.X.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.GammaNeg.P.Y.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.GammaNeg.P.Y.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.DeltaNeg.P.X.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.DeltaNeg.P.X.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.DeltaNeg.P.Y.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.G2.DeltaNeg.P.Y.A0.Limbs)

	// CommitmentKey
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.G.P.X.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.G.P.X.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.G.P.Y.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.G.P.Y.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.GRootSigmaNeg.P.X.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.GRootSigmaNeg.P.X.A0.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.GRootSigmaNeg.P.Y.A1.Limbs)
	AppendBeInPlace(&vkU64Elms, vk.CommitmentKey.GRootSigmaNeg.P.Y.A0.Limbs)

	vKSerialized := make([]uints.U8, len(vkU64Elms)*8)
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return vkHash, fmt.Errorf("uints.New: %w", err)
	}
	for i, u64Elm := range vkU64Elms {
		u64Bytes := uapi.ValueOf(u64Elm)
		ReverseInPlaceUints(&u64Bytes)
		for j := 0; j < 8; j++ {
			vKSerialized[i*8+j] = u64Bytes[j]
		}
	}

	hVK, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return vkHash, err
	}
	hVK.Write(vKSerialized)
	vkHash = hVK.Sum()

	return vkHash, nil
}

// in big-endian
func SerializePubInputs(api frontend.API, pubInputs []emulated.Element[sw_bn254.ScalarField]) (pubInputsSerialized []uints.U8, err error) {
	var pubU64Elms []frontend.Variable
	for i := 0; i < len(pubInputs); i++ {
		AppendBeInPlace(&pubU64Elms, pubInputs[i].Limbs)
	}

	pubInputsSerialized = make([]uints.U8, len(pubU64Elms)*8)
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return pubInputsSerialized, fmt.Errorf("uints.New: %w", err)
	}
	for i, u64Elm := range pubU64Elms {
		u64Bytes := uapi.ValueOf(u64Elm)
		ReverseInPlaceUints(&u64Bytes)
		for j := 0; j < 8; j++ {
			pubInputsSerialized[i*8+j] = u64Bytes[j]
		}
	}
	return pubInputsSerialized, nil
}

// returns serialized pubInputs
// Public Inputs = sha3(sha3(vKey) || sha3(pis))
func ComputePubInputs(api frontend.API, vk stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl], innerPublic []emulated.Element[sw_bn254.ScalarField]) (pubInputsSerializedComputed []uints.U8, err error) {

	// ** V Key hash **
	vkHash, err := VKHash(api, vk)
	if err != nil {
		return pubInputsSerializedComputed, fmt.Errorf("VKHash: %w", err)
	}

	// *** Inner Public inpus hash ***
	innerPublicSerialized, err := SerializePubInputs(api, innerPublic)
	if err != nil {
		return pubInputsSerializedComputed, fmt.Errorf("SerializePubInputs: %w", err)
	}
	hPis, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return pubInputsSerializedComputed, err
	}
	hPis.Write(innerPublicSerialized)
	innerPubInputsHash := hPis.Sum()

	// Public Inputs = sha3(vkHash || innerPubInputsHash)
	h, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return pubInputsSerializedComputed, err
	}
	h.Write(vkHash)
	h.Write(innerPubInputsHash)
	pubInputsSerializedComputed = h.Sum()

	return pubInputsSerializedComputed, nil
}

func VerifyPublicInputs(api frontend.API, pubInputsSerializedComputed []uints.U8, pubInputs []frontend.Variable) error {
	// create 2 bn254 elms (pub1 and pub2) out of pubInputsSerializedComputed
	pub1Bits := []frontend.Variable{}
	for i := 0; i < 16; i++ {
		pub1Bits = append(pub1Bits, Reverse(api.ToBinary(pubInputsSerializedComputed[i].Val, 8))...) // reverse bit order to make up for the next reverse
	}
	ReverseInPlace(&pub1Bits) // reverse byte order, original bit order is unaffected due to previous reverse
	pub1 := api.FromBinary(pub1Bits...)

	pub2Bits := []frontend.Variable{}
	for i := 16; i < len(pubInputsSerializedComputed); i++ {
		pub2Bits = append(pub2Bits, Reverse(api.ToBinary(pubInputsSerializedComputed[i].Val, 8))...)
	}
	ReverseInPlace(&pub2Bits)
	pub2 := api.FromBinary(pub2Bits...)

	api.AssertIsEqual(pub1, pubInputs[0])
	api.AssertIsEqual(pub2, pubInputs[1])
	return nil
}
