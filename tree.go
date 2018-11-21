package merkle

import (
	"bytes"
	"errors"
	"hash"
	"math/big"
)

const (
	DepthMax = 64
)

var (
	ErrTooLargeTreeDepth = errors.New("too large tree depth")
	ErrTooLargeLeafIndex = errors.New("too large leaf index")
)

type Tree struct {
	hasher       hash.Hash
	depth        uint64
	indexMax     uint64
	defaultNodes [][]byte
	levels       []map[uint64][]byte
}

func NewTree(hasher hash.Hash, depth uint64, leaves map[uint64][]byte) (*Tree, error) {
	if depth > DepthMax {
		return nil, ErrTooLargeTreeDepth
	}

	indexMax := new(big.Int).Lsh(big.NewInt(2), uint(depth-1)).Uint64() - 1
	if maxIndex(leaves) > indexMax {
		return nil, ErrTooLargeLeafIndex
	}

	tree := &Tree{
		hasher:       hasher,
		depth:        depth,
		indexMax:     indexMax,
		defaultNodes: make([][]byte, depth+1),
		levels:       make([]map[uint64][]byte, depth+1),
	}
	for i, _ := range tree.levels {
		tree.levels[i] = map[uint64][]byte{}
	}

	if err := tree.buildDefaultNodes(); err != nil {
		return nil, err
	}
	if err := tree.build(leaves); err != nil {
		return nil, err
	}

	return tree, nil
}

func (tree *Tree) buildDefaultNodes() error {
	node, err := tree.hash(bytes.Repeat([]byte{0x00}, tree.hasher.Size()))
	if err != nil {
		return err
	}
	tree.defaultNodes[tree.depth] = node

	for d := tree.depth; d > 0; d-- {
		node, err := tree.pairHash(tree.defaultNodes[d], tree.defaultNodes[d])
		if err != nil {
			return err
		}
		tree.defaultNodes[d-1] = node
	}

	return nil
}

func (tree *Tree) build(leaves map[uint64][]byte) error {
	for index, leaf := range leaves {
		node, err := tree.hash(leaf)
		if err != nil {
			return err
		}
		tree.levels[tree.depth][index] = node
	}

	for d := tree.depth; d > 0; d-- {
		level := tree.levels[d]

		for index, node := range level {
			if index%2 == 0 {
				siblingNode, ok := level[index+1]
				if !ok {
					siblingNode = tree.defaultNodes[d]
				}
				parentNode, err := tree.pairHash(node, siblingNode)
				if err != nil {
					return err
				}
				tree.levels[d-1][index/2] = parentNode

			} else {
				if _, ok := level[index-1]; ok {
					continue
				}
				parentNode, err := tree.pairHash(tree.defaultNodes[d], node)
				if err != nil {
					return err
				}
				tree.levels[d-1][index/2] = parentNode
			}
		}
	}

	return nil
}

func (tree *Tree) hash(b []byte) ([]byte, error) {
	tree.hasher.Reset()
	if _, err := tree.hasher.Write(b); err != nil {
		return nil, err
	}
	return tree.hasher.Sum(nil), nil
}

func (tree *Tree) pairHash(b1, b2 []byte) ([]byte, error) {
	tree.hasher.Reset()
	if _, err := tree.hasher.Write(b1); err != nil {
		return nil, err
	}
	if _, err := tree.hasher.Write(b2); err != nil {
		return nil, err
	}
	return tree.hasher.Sum(nil), nil
}

func (tree *Tree) Root() []byte {
	if root, ok := tree.levels[0][0]; ok {
		return root
	}
	return tree.defaultNodes[0]
}
