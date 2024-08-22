package prove

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Electron-Labs/quantum-gnark-circuits/aggregator"
	circuit_data "github.com/Electron-Labs/quantum-gnark-circuits/circuit_data"
	"github.com/Electron-Labs/quantum-gnark-circuits/cmd"
	imt "github.com/Electron-Labs/quantum-gnark-circuits/indexed_merkle_tree"
	verifier_gnark "github.com/Electron-Labs/quantum-gnark-circuits/quantum_reduction_circuits/verifier/gnark_groth16"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/spf13/cobra"
)

// e2eCmd represents the e2e command
var e2eCmd = &cobra.Command{
	Use:   "e2e",
	Short: "Generate groth16 proofs, imt proof, and aggrregated proof",
	Run: func(cmd *cobra.Command, args []string) {
		err := proveE2e()
		if err != nil {
			panic(fmt.Errorf("error: %v", err))
		}
	},
}

func init() {
	proveCmd.AddCommand(e2eCmd)
}

func proveE2e() error {
	fmt.Println("setting up reduction artifacts...")
	reductionPk, err := readPk(cmd.OutputDir + "/reduction/reduction_pk.bin")
	if err != nil {
		return err
	}
	reductionCs, err := readCs(cmd.OutputDir + "/reduction/reduction_cs.bin")
	if err != nil {
		return err
	}
	reductionVk, err := readVk(cmd.OutputDir + "/reduction/reduction_vk.json")
	if err != nil {
		return err
	}
	fmt.Println("done")
	fmt.Println("setting up imt artifacts...")
	imtPk, err := readPk(cmd.OutputDir + "/imt/imt_pk.bin")
	if err != nil {
		return err
	}
	imtCs, err := readCs(cmd.OutputDir + "/imt/imt_cs.bin")
	if err != nil {
		return err
	}
	imtVk, err := readVk(cmd.OutputDir + "/imt/imt_vk.json")
	if err != nil {
		return err
	}
	fmt.Println("done")
	fmt.Println("setting up agg artifacts...")
	aggPk, err := readPk(cmd.OutputDir + "/agg/agg_pk.bin")
	if err != nil {
		return err
	}
	aggCs, err := readCs(cmd.OutputDir + "/agg/agg_cs.bin")
	if err != nil {
		return err
	}
	aggVk, err := readVk(cmd.OutputDir + "/agg/agg_vk.json")
	if err != nil {
		return err
	}
	fmt.Println("done")

	e2eProve := time.Now()
	fmt.Println("creating proofs...")

	protocolVks, protocolProofs, protocolPis, err := readProofsVksPis()
	if err != nil {
		return err
	}
	protocolVkHashes, err := hashVks(protocolVks)
	if err != nil {
		return err
	}
	pisHashes, err := hashPis(protocolPis)
	if err != nil {
		return err
	}

	reductionVkHash, err := verifier_gnark.GetReductionVKHash(&reductionVk)
	if err != nil {
		return err
	}
	imtAssignment, newRoot, err := getNativeImt(protocolVkHashes, pisHashes, reductionVkHash)
	if err != nil {
		return err
	}

	reductionVkWitness := verifier_gnark.VK{}
	bytesVK, err := os.ReadFile(cmd.OutputDir + "/reduction/reduction_vk.json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytesVK, &reductionVkWitness)
	if err != nil {
		return err
	}

	gnarkVerifiers := make([]aggregator.NativeGnarkVerifier, len(protocolProofs))

	var proveWg sync.WaitGroup
	for i := 0; i < len(protocolProofs); i++ {
		proveWg.Add(1)

		go func(i int) {
			defer proveWg.Done()

			pass, msg, proof, pis := protocolProofs[i].ProveGroth16CircuitWithCs(
				reductionCs,
				reductionPk,
				&reductionVk,
				protocolVks[i],
				protocolPis[i],
			)
			if !pass {
				panic(fmt.Sprintf("Failed to prove protocol %d - %s", i, msg))
			}
			proof_ := verifier_gnark.GnarkProofToBackendProof(*proof.(*groth16_bn254.Proof))
			pisFr := make(fr_bn254.Vector, len(pis))
			for i, v := range pis {
				pisFr[i].SetString(v)
			}
			gnarkVerifiers[i] = aggregator.NativeGnarkVerifier{
				Proof:     proof_,
				VK:        reductionVkWitness,
				PubInputs: pisFr,
			}
		}(i)
	}

	imtVkWitness := verifier_gnark.VK{}
	bytesVK, err = os.ReadFile(cmd.OutputDir + "/imt/imt_vk.json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytesVK, &imtVkWitness)
	if err != nil {
		return err
	}

	var imtVerifier aggregator.NativeGnarkVerifier

	proveWg.Add(1)

	go func() {
		defer proveWg.Done()

		pass, msg, proof, pis := imt.ProveImtCircuit(imtCs, imtPk, &imtVk, *imtAssignment)
		if !pass {
			panic(fmt.Sprintf("Failed to prove imt - %s", msg))
		}
		proof_ := verifier_gnark.GnarkProofToBackendProof(*proof.(*groth16_bn254.Proof))
		pisFr := make(fr_bn254.Vector, len(pis))
		for i, v := range pis {
			pisFr[i].SetString(v)
		}
		imtVerifier = aggregator.NativeGnarkVerifier{
			Proof:     proof_,
			VK:        imtVkWitness,
			PubInputs: pisFr,
		}
	}()

	proveWg.Wait()
	fmt.Println("reduction and imt proofs done")

	nativeAggregator, err := getNativeAggregator(
		gnarkVerifiers,
		imtVerifier,
		protocolVkHashes,
		pisHashes,
		imtAssignment.OldRoot,
		newRoot,
	)
	if err != nil {
		return err
	}

	pass, msg, proof, pis := aggregator.ProveAggCircuit(aggCs, aggPk, &aggVk, *nativeAggregator)
	if !pass {
		return fmt.Errorf("failed to prove agg circuit - %s", msg)
	}

	fmt.Println("done")
	fmt.Printf("total proving time %.2f seconds\n", time.Since(e2eProve).Seconds())

	fmt.Println("dumping proofs and pis")
	proofBytes, err := json.MarshalIndent(proof, "", "    ")
	if err != nil {
		return err
	}
	fileProof, err := os.Create(cmd.OutputDir + "/agg/agg_proof.json")
	if err != nil {
		return err
	}
	defer fileProof.Close()
	_, err = fileProof.Write(proofBytes)
	if err != nil {
		return err
	}

	pisBytes, err := json.MarshalIndent(pis, "", "    ")
	if err != nil {
		return err
	}
	filePis, err := os.Create(cmd.OutputDir + "/agg/agg_pis.json")
	if err != nil {
		return err
	}
	defer filePis.Close()
	_, err = filePis.Write(pisBytes)
	if err != nil {
		return err
	}

	return nil
}

func getNativeAggregator(
	protocolVerifiers []aggregator.NativeGnarkVerifier,
	imtVerifier aggregator.NativeGnarkVerifier,
	protocolVkHashes []circuit_data.NativeKeccakHash,
	pisHashes []circuit_data.NativeKeccakHash,
	oldRoot circuit_data.NativeKeccakHash,
	newRoot circuit_data.NativeKeccakHash,
) (*aggregator.NativeAggregator, error) {
	pubInputs, err := aggregator.GetAggregatorPublicInputs(protocolVkHashes, protocolVerifiers, pisHashes, oldRoot, newRoot, imtVerifier)
	if err != nil {
		return nil, err
	}

	return &aggregator.NativeAggregator{
		ReductionCircuitDataVec: protocolVerifiers,
		ImtReductionCircuitData: imtVerifier,
		ProtocolVKHashes:        protocolVkHashes,
		ProtocolPisHashes:       pisHashes,
		OldRoot:                 oldRoot,
		NewRoot:                 newRoot,
		PubInputs:               pubInputs[:],
	}, nil
}
