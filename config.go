package merkle

import (
	"hash"
)

type Config struct {
	hasher hash.Hash
	depth  uint64
}

func NewConfig(hasher hash.Hash, depth uint64) *Config {
	return &Config{
		hasher: hasher,
		depth:  depth,
	}
}
