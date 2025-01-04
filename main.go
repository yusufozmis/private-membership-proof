package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Circuit struct {
	merkleProof []string
	merkleRoot  string
	target      string
}

type Node struct {
	Hash  string
	Left  *Node
	Right *Node
}

func newNode(left, right *Node, data string) *Node {
	if left == nil && right == nil {
		hash := sha256.Sum256([]byte(data))
		return &Node{Hash: hex.EncodeToString(hash[:])}
	}
	concat := left.Hash + right.Hash
	concatHash := sha256.Sum256([]byte(concat))
	return &Node{Left: left, Right: right, Hash: hex.EncodeToString(concatHash[:])}
}

func merkleTree(data []string) [][]string {
	var hashLevels [][]string
	leafCount := len(data)
	if leafCount == 0 {
		return nil
	}
	var leafHashes []string
	var nodeList []*Node
	for i, leaf := range data {
		nodeList = append(nodeList, newNode(nil, nil, leaf))
		leafHashes = append(leafHashes, nodeList[i].Hash)
	}
	hashLevels = append(hashLevels, leafHashes)

	for len(nodeList) > 1 {
		var parentNodes []*Node
		var levelHashes []string
		for i := 0; i < len(nodeList); i += 2 {
			var parent *Node
			if i+1 < len(nodeList) {
				parent = newNode(nodeList[i], nodeList[i+1], "")
			} else {
				parent = newNode(nodeList[i], nodeList[i], "")
			}
			parentNodes = append(parentNodes, parent)
			levelHashes = append(levelHashes, parent.Hash)
		}
		nodeList = parentNodes
		hashLevels = append(hashLevels, levelHashes)
	}

	return hashLevels
}

func merkleProof(data []string, target string) ([]string, error) {

	hashLevels := merkleTree(data)
	if len(hashLevels) == 0 {
		return nil, fmt.Errorf("no tree")
	}
	var targetIndex int
	found := false
	for i, leaf := range data {
		if leaf == target {
			targetIndex = i
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("public key does not exist")
	}
	proof := []string{}
	for level := 0; level < len(hashLevels)-1; level++ {
		var siblingIndex int
		if targetIndex%2 == 0 {
			siblingIndex = targetIndex + 1
		} else {
			siblingIndex = siblingIndex - 1
		}
		if siblingIndex < len(hashLevels[level]) {
			proof = append(proof, hashLevels[level][siblingIndex])
		}
		targetIndex /= 2
	}

	return proof, nil
}

func (circuit *Circuit) Define(api frontend.API) error {

	leafHash := sha256.Sum256([]byte(circuit.target))
	currentHash := hex.EncodeToString(leafHash[:])
	for _, p := range circuit.merkleProof {
		concat := currentHash + p
		concatHash := sha256.Sum256([]byte(concat))
		currentHash = hex.EncodeToString(concatHash[:])
	}

	currentHashBigInt, _ := new(big.Int).SetString(currentHash, 16)
	merkleRootBigInt, _ := new(big.Int).SetString(circuit.merkleRoot, 16)

	expectedRoot, _ := api.ConstantValue(merkleRootBigInt)
	calculatedHash, _ := api.ConstantValue(currentHashBigInt)

	api.AssertIsEqual(calculatedHash, expectedRoot)

	return nil
}
func keyGen() string {
	prv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	publicX, _ := prv.ScalarBaseMult(prv.D.Bytes())
	return hex.EncodeToString(publicX.Bytes())
}
func main() {

	var data []string // publicKey list.
	//I have not implemented the logic on how public keys are collected
	//an api can be implemented
	for i := 0; i < 10; i++ { // 10 is the number of people in friend group
		data = append(data, keyGen())
	}
	target := data[0]
	merkleproof, err := merkleProof(data, target)
	if err != nil {
		fmt.Println("Error generating proof:", err)
		return
	}

	hashLevels := merkleTree(data)
	rootHash := hashLevels[len(hashLevels)-1][0]

	var circuit Circuit
	circuit.target = target
	circuit.merkleProof = merkleproof
	circuit.merkleRoot = rootHash

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Failed to compile circuit: %v\n", err)
		return
	}

	wtnss, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness: %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Failed to setup Groth16: %v\n", err)
		return
	}

	proof, err := groth16.Prove(r1cs, pk, wtnss)
	if err != nil {
		fmt.Printf("Failed to generate proof: %v\n", err)
		return
	}

	vrfy := groth16.Verify(proof, vk, wtnss)
	//verifier logic can be implemented in a smart contract
	if vrfy == nil {
		fmt.Println("Proof verified")
	} else {
		fmt.Println("Invalid proof")
	}

}
