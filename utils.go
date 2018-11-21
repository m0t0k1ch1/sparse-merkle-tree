package merkle

func maxIndex(leaves map[uint64][]byte) uint64 {
	max := uint64(0)
	for i, _ := range leaves {
		if i > max {
			max = i
		}
	}
	return max
}
