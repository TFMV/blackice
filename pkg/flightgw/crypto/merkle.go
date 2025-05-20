package crypto

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// MerkleVerifier handles verification of Merkle proofs for data integrity
type MerkleVerifier struct {
	initialized bool
}

// NewMerkleVerifier creates a new MerkleVerifier
func NewMerkleVerifier() (*MerkleVerifier, error) {
	return &MerkleVerifier{
		initialized: true,
	}, nil
}

// VerifyProof verifies a Merkle proof against a root hash and data hash
func (v *MerkleVerifier) VerifyProof(proof *blackicev1.MerkleProof, data []byte) (bool, error) {
	if !v.initialized {
		return false, errors.New("merkle verifier not properly initialized")
	}

	if proof == nil {
		return false, errors.New("proof is nil")
	}

	if len(proof.RootHash) == 0 {
		return false, errors.New("root hash is empty")
	}

	if len(proof.Path) == 0 {
		// Special case: If there's only one item in the tree, verify directly against root
		return verifyEmptyPath(proof, data)
	}

	// Calculate the hash of the data using the specified algorithm
	dataHash, err := calculateHash(data, proof.HashAlgorithm)
	if err != nil {
		return false, err
	}

	// If the proof contains a leaf hash, verify it matches our calculated hash
	if len(proof.LeafHash) > 0 && !bytes.Equal(proof.LeafHash, dataHash) {
		log.Debug().
			Hex("calculated_hash", dataHash).
			Hex("proof_leaf_hash", proof.LeafHash).
			Msg("Leaf hash mismatch")
		return false, nil
	}

	// Start with the data hash (or the provided leaf hash)
	currentHash := dataHash
	if len(proof.LeafHash) > 0 {
		currentHash = proof.LeafHash
	}

	// Traverse the path to reconstruct the root hash
	for _, node := range proof.Path {
		if node == nil || len(node.Hash) == 0 {
			return false, errors.New("invalid node in proof path")
		}

		// Combine the current hash with the path node's hash
		// The position (left/right) determines the order of concatenation
		if node.Position == blackicev1.MerkleNode_LEFT {
			currentHash = combinedHash(node.Hash, currentHash, proof.HashAlgorithm)
		} else {
			currentHash = combinedHash(currentHash, node.Hash, proof.HashAlgorithm)
		}
	}

	// Verify the computed root matches the expected root
	if !bytes.Equal(currentHash, proof.RootHash) {
		log.Debug().
			Hex("computed_root", currentHash).
			Hex("expected_root", proof.RootHash).
			Msg("Root hash mismatch")
		return false, nil
	}

	return true, nil
}

// VerifyStreamProof verifies a Merkle proof for streaming data
// This is used for Merkle Stream Verification where data arrives in chunks
func (v *MerkleVerifier) VerifyStreamProof(
	proof *blackicev1.MerkleProof,
	chunkData []byte,
	sequenceNumber int64,
	isLastChunk bool,
) (bool, error) {
	if !v.initialized {
		return false, errors.New("merkle verifier not properly initialized")
	}

	if proof == nil {
		return false, errors.New("stream proof is nil")
	}

	// For stream verification, we include the sequence number in the hash calculation
	// to prevent reordering attacks
	seqBytes := []byte(fmt.Sprintf("%d", sequenceNumber))
	combinedData := append(chunkData, seqBytes...)

	// Add a flag for last chunk to prevent truncation attacks
	if isLastChunk {
		combinedData = append(combinedData, []byte("LAST")...)
	}

	// Verify using the standard proof verification
	return v.VerifyProof(proof, combinedData)
}

// verifyEmptyPath handles the special case where there's no path (single item tree)
func verifyEmptyPath(proof *blackicev1.MerkleProof, data []byte) (bool, error) {
	// Calculate hash of the data
	dataHash, err := calculateHash(data, proof.HashAlgorithm)
	if err != nil {
		return false, err
	}

	// For a tree with only one entry, the data hash should equal the root hash
	if !bytes.Equal(dataHash, proof.RootHash) {
		log.Debug().
			Hex("data_hash", dataHash).
			Hex("root_hash", proof.RootHash).
			Msg("Root hash does not match data hash for single-item tree")
		return false, nil
	}

	return true, nil
}

// calculateHash calculates the hash of data using the specified algorithm
func calculateHash(data []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "SHA256":
		hash := sha256.Sum256(data)
		return hash[:], nil
	case "SHA512":
		hash := sha512.Sum512(data)
		return hash[:], nil
	case "SHA3-256":
		// We would implement SHA3 here
		return nil, errors.New("SHA3-256 not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// combinedHash combines two hashes according to the Merkle tree structure
func combinedHash(left, right []byte, algorithm string) []byte {
	// Concatenate the hashes
	combined := append(left, right...)

	// Hash the combined value
	switch algorithm {
	case "SHA256":
		hash := sha256.Sum256(combined)
		return hash[:]
	case "SHA512":
		hash := sha512.Sum512(combined)
		return hash[:]
	case "SHA3-256":
		// We would implement SHA3 here if needed
		return nil
	default:
		return nil
	}
}
