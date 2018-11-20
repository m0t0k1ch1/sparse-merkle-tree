package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

var testConfig = &Config{
	hasher:   sha256.New(),
	depth:    2,
	hashSize: 32,
}

func TestTree(t *testing.T) {
	type input struct {
		config *Config
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
			"success",
			input{
				testConfig,
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

			tree, err := NewTree(in.config, in.leaves)
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
