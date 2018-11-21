package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

func TestTree(t *testing.T) {
	type input struct {
		hasher hash.Hash
		depth  uint64
		leaves map[uint64][]byte
	}
	type output struct {
		rootStr string
		err     error
	}
	testCases := []struct {
		name string
		in   input
		out  output
	}{
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
					5: nil,
				},
			},
			output{
				"",
				ErrTooLargeLeafIndex,
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
				rootStr := hex.EncodeToString(tree.Root())
				if rootStr != out.rootStr {
					t.Errorf("expected: %s, actual: %s", out.rootStr, rootStr)
				}
			}
		})
	}
}
