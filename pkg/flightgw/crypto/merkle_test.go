package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

func TestMerkleVerifier(t *testing.T) {
	verifier, err := NewMerkleVerifier()
	if err != nil {
		t.Fatalf("Failed to create merkle verifier: %v", err)
	}

	if verifier == nil {
		t.Fatal("Merkle verifier is nil")
	}

	if !verifier.initialized {
		t.Fatal("Merkle verifier is not initialized")
	}
}

func TestVerifyProofSingleNodeTree(t *testing.T) {
	verifier, err := NewMerkleVerifier()
	if err != nil {
		t.Fatalf("Failed to create merkle verifier: %v", err)
	}

	// Test data
	testData := []byte("Test data for single node Merkle tree")

	// Calculate root hash (for a single node tree, it's just the hash of the data)
	hash := sha256.Sum256(testData)
	rootHash := hash[:]

	// Create a proof with no path (single node tree)
	proof := &blackicev1.MerkleProof{
		RootHash:      rootHash,
		LeafHash:      nil,
		HashAlgorithm: "SHA256",
		Path:          []*blackicev1.MerkleNode{},
	}

	// Verify the proof
	valid, err := verifier.VerifyProof(proof, testData)
	if err != nil {
		t.Fatalf("Error during proof verification: %v", err)
	}

	if !valid {
		t.Fatal("Single node proof verification failed")
	}

	// Tamper with the data and verify it fails
	tamperedData := append([]byte{}, testData...)
	tamperedData[0] ^= 0xFF // Flip bits in first byte

	valid, err = verifier.VerifyProof(proof, tamperedData)
	if err != nil {
		t.Logf("Expected error for tampered data: %v", err)
	}

	if valid {
		t.Fatal("Proof verification should have failed with tampered data")
	}
}

func TestVerifyProofMultiNodeTree(t *testing.T) {
	verifier, err := NewMerkleVerifier()
	if err != nil {
		t.Fatalf("Failed to create merkle verifier: %v", err)
	}

	// Test scenarios
	testCases := []struct {
		name          string
		hashAlgorithm string
		hashFunc      func(data []byte) []byte
	}{
		{
			name:          "SHA256",
			hashAlgorithm: "SHA256",
			hashFunc: func(data []byte) []byte {
				hash := sha256.Sum256(data)
				return hash[:]
			},
		},
		{
			name:          "SHA512",
			hashAlgorithm: "SHA512",
			hashFunc: func(data []byte) []byte {
				hash := sha512.Sum512(data)
				return hash[:]
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a simple 4-leaf Merkle tree for testing
			// This simulates a balanced Merkle tree with 4 leaves: [data1, data2, data3, data4]
			data1 := []byte("Leaf data 1")
			data2 := []byte("Leaf data 2")
			data3 := []byte("Leaf data 3")
			data4 := []byte("Leaf data 4")

			// Calculate leaf hashes
			hash1 := tc.hashFunc(data1)
			hash2 := tc.hashFunc(data2)
			hash3 := tc.hashFunc(data3)
			hash4 := tc.hashFunc(data4)

			// Calculate internal nodes
			combined1 := append(hash1, hash2...)
			internalHash1 := tc.hashFunc(combined1)

			combined2 := append(hash3, hash4...)
			internalHash2 := tc.hashFunc(combined2)

			// Calculate root
			combinedRoot := append(internalHash1, internalHash2...)
			rootHash := tc.hashFunc(combinedRoot)

			// Create a proof for data1 (left-most leaf)
			// Path: hash2 (right sibling), internalHash2 (right sibling at next level)
			proofForData1 := &blackicev1.MerkleProof{
				RootHash:      rootHash,
				LeafHash:      hash1,
				HashAlgorithm: tc.hashAlgorithm,
				Path: []*blackicev1.MerkleNode{
					{
						Hash:     hash2,
						Position: blackicev1.MerkleNode_RIGHT,
					},
					{
						Hash:     internalHash2,
						Position: blackicev1.MerkleNode_RIGHT,
					},
				},
			}

			// Verify the proof for data1
			valid, err := verifier.VerifyProof(proofForData1, data1)
			if err != nil {
				t.Fatalf("Error during proof verification for data1: %v", err)
			}

			if !valid {
				t.Fatal("Proof verification failed for data1")
			}

			// Create a proof for data4 (right-most leaf)
			// Path: hash3 (left sibling), internalHash1 (left sibling at next level)
			proofForData4 := &blackicev1.MerkleProof{
				RootHash:      rootHash,
				LeafHash:      hash4,
				HashAlgorithm: tc.hashAlgorithm,
				Path: []*blackicev1.MerkleNode{
					{
						Hash:     hash3,
						Position: blackicev1.MerkleNode_LEFT,
					},
					{
						Hash:     internalHash1,
						Position: blackicev1.MerkleNode_LEFT,
					},
				},
			}

			// Verify the proof for data4
			valid, err = verifier.VerifyProof(proofForData4, data4)
			if err != nil {
				t.Fatalf("Error during proof verification for data4: %v", err)
			}

			if !valid {
				t.Fatal("Proof verification failed for data4")
			}

			// Test with tampered data
			tamperedData4 := append([]byte{}, data4...)
			tamperedData4[0] ^= 0xFF // Flip bits in first byte

			valid, err = verifier.VerifyProof(proofForData4, tamperedData4)
			if err != nil {
				t.Logf("Expected error for tampered data: %v", err)
			}

			if valid {
				t.Fatal("Proof verification should have failed with tampered data")
			}

			// Test with tampered proof (change a path node)
			tamperedProof := &blackicev1.MerkleProof{
				RootHash:      rootHash,
				LeafHash:      hash4,
				HashAlgorithm: tc.hashAlgorithm,
				Path: []*blackicev1.MerkleNode{
					{
						Hash:     hash3,
						Position: blackicev1.MerkleNode_LEFT,
					},
					{
						// Wrong hash at this level
						Hash:     tc.hashFunc([]byte("wrong hash")),
						Position: blackicev1.MerkleNode_LEFT,
					},
				},
			}

			valid, err = verifier.VerifyProof(tamperedProof, data4)
			if err != nil {
				t.Logf("Expected error for tampered proof: %v", err)
			}

			if valid {
				t.Fatal("Proof verification should have failed with tampered proof")
			}
		})
	}
}

func TestVerifyStreamProof(t *testing.T) {
	verifier, err := NewMerkleVerifier()
	if err != nil {
		t.Fatalf("Failed to create merkle verifier: %v", err)
	}

	// Test data chunks
	chunk1 := []byte("Chunk 1 of streaming data")
	chunk2 := []byte("Chunk 2 of streaming data")
	chunk3 := []byte("Chunk 3 of streaming data")

	// Sequence numbers
	seq1 := int64(1)
	seq2 := int64(2)
	seq3 := int64(3)

	// Combine data with sequence for verification
	combinedData1 := append(chunk1, []byte(fmt.Sprintf("%d", seq1))...)
	combinedData2 := append(chunk2, []byte(fmt.Sprintf("%d", seq2))...)
	combinedData3 := append(chunk3, []byte(fmt.Sprintf("%d", seq3))...)

	// Mark the last chunk
	lastCombinedData := append(combinedData3, []byte("LAST")...)

	// Calculate hashes for each chunk
	hash1 := sha256.Sum256(combinedData1)
	hash2 := sha256.Sum256(combinedData2)
	hash3 := sha256.Sum256(lastCombinedData)

	// Build a simple Merkle tree from these hashes
	combined1 := append(hash1[:], hash2[:]...)
	internalHash1 := sha256.Sum256(combined1)

	combined2 := append(internalHash1[:], hash3[:]...)
	rootHash := sha256.Sum256(combined2)

	// Create a proof for the last chunk
	proofForLastChunk := &blackicev1.MerkleProof{
		RootHash:      rootHash[:],
		LeafHash:      hash3[:],
		HashAlgorithm: "SHA256",
		Path: []*blackicev1.MerkleNode{
			{
				Hash:     internalHash1[:],
				Position: blackicev1.MerkleNode_LEFT,
			},
		},
	}

	// Verify the stream proof for the last chunk
	valid, err := verifier.VerifyStreamProof(proofForLastChunk, chunk3, seq3, true)
	if err != nil {
		t.Fatalf("Error during stream proof verification: %v", err)
	}

	if !valid {
		t.Fatal("Stream proof verification failed")
	}

	// Test with incorrect sequence number (reordering attack)
	valid, err = verifier.VerifyStreamProof(proofForLastChunk, chunk3, seq2, true)
	if err != nil {
		t.Logf("Expected error with incorrect sequence: %v", err)
	}

	if valid {
		t.Fatal("Stream proof verification should have failed with incorrect sequence")
	}

	// Test with last flag set incorrectly (truncation attack)
	valid, err = verifier.VerifyStreamProof(proofForLastChunk, chunk3, seq3, false)
	if err != nil {
		t.Logf("Expected error with incorrect last flag: %v", err)
	}

	if valid {
		t.Fatal("Stream proof verification should have failed with incorrect last flag")
	}
}

func TestMerkleVerifierErrors(t *testing.T) {
	verifier, err := NewMerkleVerifier()
	if err != nil {
		t.Fatalf("Failed to create merkle verifier: %v", err)
	}

	// Test data
	testData := []byte("Test data for error cases")

	// Test with nil proof
	valid, err := verifier.VerifyProof(nil, testData)
	if err == nil {
		t.Fatal("Expected error for nil proof, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with nil proof")
	}

	// Test with empty root hash
	emptyRootProof := &blackicev1.MerkleProof{
		RootHash:      []byte{},
		HashAlgorithm: "SHA256",
		Path:          []*blackicev1.MerkleNode{},
	}

	valid, err = verifier.VerifyProof(emptyRootProof, testData)
	if err == nil {
		t.Fatal("Expected error for empty root hash, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with empty root hash")
	}

	// Test with invalid path node
	invalidNodeProof := &blackicev1.MerkleProof{
		RootHash:      calculateSHA256Hash(testData),
		HashAlgorithm: "SHA256",
		Path: []*blackicev1.MerkleNode{
			{
				Hash:     []byte{}, // Empty hash
				Position: blackicev1.MerkleNode_LEFT,
			},
		},
	}

	valid, err = verifier.VerifyProof(invalidNodeProof, testData)
	if err == nil {
		t.Fatal("Expected error for invalid path node, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with invalid path node")
	}

	// Test with unsupported hash algorithm
	unsupportedAlgoProof := &blackicev1.MerkleProof{
		RootHash:      calculateSHA256Hash(testData),
		HashAlgorithm: "UNSUPPORTED-HASH",
		Path:          []*blackicev1.MerkleNode{},
	}

	valid, err = verifier.VerifyProof(unsupportedAlgoProof, testData)
	if err == nil {
		t.Fatal("Expected error for unsupported hash algorithm, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with unsupported hash algorithm")
	}

	// Test with nil proof in stream verification
	valid, err = verifier.VerifyStreamProof(nil, testData, 1, false)
	if err == nil {
		t.Fatal("Expected error for nil stream proof, got none")
	}
	if valid {
		t.Fatal("Stream verification should have failed with nil proof")
	}
}

// Helper function to calculate SHA256 hash and return it as a slice
func calculateSHA256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
