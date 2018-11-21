package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

func newTestTree(t *testing.T) *Tree {
	tree, err := NewTree(sha256.New(), 3, map[uint64][]byte{
		0: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		3: []byte{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestTree(t *testing.T) {
	type input struct {
		hasher hash.Hash
		depth  uint64
		leaves map[uint64][]byte
	}
	type output struct {
		rootHex string
		err     error
	}
	testCases := []struct {
		name string
		in   input
		out  output
	}{
		{
			"failure: too large tree depth",
			input{
				sha256.New(),
				65,
				nil,
			},
			output{
				"",
				ErrTooLargeTreeDepth,
			},
		},
		{
			"failure: too large leaf index",
			input{
				sha256.New(),
				2,
				map[uint64][]byte{
					4: nil,
				},
			},
			output{
				"",
				ErrTooLargeLeafIndex,
			},
		},
		{
			"success: default",
			input{
				sha256.New(),
				2,
				nil,
			},
			output{
				"1223349a40d2ee10bd1bebb5889ef8018c8bc13359ed94b387810af96c6e4268",
				nil,
			},
		},
		{
			"success",
			input{
				sha256.New(),
				2,
				map[uint64][]byte{
					0: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					3: []byte{0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
				},
			},
			output{
				"63b837bc262a357e26206290926736b07ad45ddc1e15b5a7e0092b708c093104",
				nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			in, out := tc.in, tc.out

			tree, err := NewTree(in.hasher, in.depth, in.leaves)
			if err != out.err {
				t.Errorf("expected: %v, actual: %v", out.err, err)
			}
			if err == nil {
				rootHex := hex.EncodeToString(tree.Root())
				if rootHex != out.rootHex {
					t.Errorf("expected: %s, actual: %s", out.rootHex, rootHex)
				}
			}
		})
	}
}

func TestTree_CreateMembershipProof(t *testing.T) {
	type input struct {
		index uint64
	}
	type output struct {
		proofHex string
		err      error
	}
	testCases := []struct {
		name string
		tree *Tree
		in   input
		out  output
	}{
		{
			"failure: too large leaf index",
			newTestTree(t),
			input{
				8,
			},
			output{
				"",
				ErrTooLargeLeafIndex,
			},
		},
		{
			"success: inclusion",
			newTestTree(t),
			input{
				0,
			},
			output{
				"00000000000000021b6d2a8dca8d96e6dfa28a826037521bb587d3cb435c44c90139e87a7a4fa164",
				nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tree, in, out := tc.tree, tc.in, tc.out

			proof, err := tree.CreateMembershipProof(in.index)
			if err != out.err {
				t.Errorf("expected: %v, actual: %v", out.err, err)
			}
			if err == nil {
				proofHex := hex.EncodeToString(proof)
				if proofHex != out.proofHex {
					t.Errorf("expected: %s, actual: %s", out.proofHex, proofHex)
				}
			}
		})
	}
}

func TestTree_VerifyMembershipProof(t *testing.T) {
	type input struct {
		index    uint64
		proofHex string
	}
	type output struct {
		ok  bool
		err error
	}
	testCases := []struct {
		name string
		tree *Tree
		in   input
		out  output
	}{
		{
			"failure: too large leaf index",
			newTestTree(t),
			input{
				8,
				"",
			},
			output{
				false,
				ErrTooLargeLeafIndex,
			},
		},
		{
			"failure: too large proof size",
			newTestTree(t),
			input{
				0,
				"0000000000000000" +
					"0000000000000000000000000000000000000000000000000000000000000000" +
					"0000000000000000000000000000000000000000000000000000000000000000" +
					"0000000000000000000000000000000000000000000000000000000000000000" +
					"00",
			},
			output{
				false,
				ErrTooLargeProofSize,
			},
		},
		{
			"failure: invalid proof size",
			newTestTree(t),
			input{
				0,
				"0000000000000000" +
					"0000000000000000000000000000000000000000000000000000000000000000" +
					"0000000000000000000000000000000000000000000000000000000000000000" +
					"00000000000000000000000000000000000000000000000000000000000000",
			},
			output{
				false,
				ErrInvalidProofSize,
			},
		},
		{
			"failure: invalid proof head",
			newTestTree(t),
			input{
				0,
				"00000000000000011b6d2a8dca8d96e6dfa28a826037521bb587d3cb435c44c90139e87a7a4fa164",
			},
			output{
				false,
				nil,
			},
		},
		{
			"failure: invalid proof",
			newTestTree(t),
			input{
				0,
				"00000000000000021b6d2a8dca8d96e6dfa28a826037521bb587d3cb435c44c90139e87a7a4fa163",
			},
			output{
				false,
				nil,
			},
		},
		{
			"success",
			newTestTree(t),
			input{
				0,
				"00000000000000021b6d2a8dca8d96e6dfa28a826037521bb587d3cb435c44c90139e87a7a4fa164",
			},
			output{
				true,
				nil,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tree, in, out := tc.tree, tc.in, tc.out

			proof, err := hex.DecodeString(in.proofHex)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := tree.VerifyMembershipProof(in.index, proof)
			if err != out.err {
				t.Errorf("expected: %v, actual: %v", out.err, err)
			}
			if err == nil {
				if ok != out.ok {
					t.Errorf("expected: %t, actual: %t", out.ok, ok)
				}
			}
		})
	}
}
