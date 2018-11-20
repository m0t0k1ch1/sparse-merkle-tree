package merkle

type Tree struct {
	config       *Config
	defaultNodes [][]byte
	levels       []map[uint64][]byte
}

func NewTree(conf *Config, leaves map[uint64][]byte) (*Tree, error) {
	tree := &Tree{
		config:       conf,
		defaultNodes: make([][]byte, conf.depth+1),
		levels:       make([]map[uint64][]byte, conf.depth+1),
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
	conf := tree.config

	node, err := tree.hash(make([]byte, conf.hashSize, conf.hashSize))
	if err != nil {
		return err
	}
	tree.defaultNodes[conf.depth] = node

	for d := conf.depth; d > 0; d-- {
		node, err := tree.pairHash(tree.defaultNodes[d], tree.defaultNodes[d])
		if err != nil {
			return err
		}
		tree.defaultNodes[d-1] = node
	}

	return nil
}

func (tree *Tree) build(leaves map[uint64][]byte) error {
	conf := tree.config

	for index, leaf := range leaves {
		node, err := tree.hash(leaf)
		if err != nil {
			return err
		}
		tree.levels[conf.depth][index] = node
	}

	for d := conf.depth; d > 0; d-- {
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
				if _, ok := level[index-1]; !ok {
					parentNode, err := tree.pairHash(tree.defaultNodes[d], node)
					if err != nil {
						return err
					}
					tree.levels[d-1][index/2] = parentNode
				}
			}
		}
	}

	return nil
}

func (tree *Tree) hash(b []byte) ([]byte, error) {
	hasher := tree.config.hasher
	hasher.Reset()
	if _, err := hasher.Write(b); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (tree *Tree) pairHash(b1, b2 []byte) ([]byte, error) {
	hasher := tree.config.hasher
	hasher.Reset()
	if _, err := hasher.Write(b1); err != nil {
		return nil, err
	}
	if _, err := hasher.Write(b2); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (tree *Tree) Root() []byte {
	if root, ok := tree.levels[0][0]; ok {
		return root
	}
	return tree.defaultNodes[0]
}
