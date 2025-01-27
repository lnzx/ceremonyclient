package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"

	rbls48581 "source.quilibrium.com/quilibrium/monorepo/bls48581"
)

func init() {
	gob.Register(&VectorCommitmentLeafNode{})
	gob.Register(&VectorCommitmentBranchNode{})
}

const (
	BranchNodes = 64
	BranchBits  = 6 // log2(64)
	BranchMask  = BranchNodes - 1
)

type VectorCommitmentNode interface {
	Commit() []byte
}

type VectorCommitmentLeafNode struct {
	Key        []byte
	Value      []byte
	Commitment []byte
}

type VectorCommitmentBranchNode struct {
	Prefix     []int
	Children   [BranchNodes]VectorCommitmentNode
	Commitment []byte
}

func (n *VectorCommitmentLeafNode) Commit() []byte {
	if n.Commitment == nil {
		h := sha512.New()
		h.Write([]byte{0})
		h.Write(n.Key)
		h.Write(n.Value)
		n.Commitment = h.Sum(nil)
	}
	return n.Commitment
}

func (n *VectorCommitmentBranchNode) Commit() []byte {
	if n.Commitment == nil {
		data := []byte{}
		for _, child := range n.Children {
			if child != nil {
				out := child.Commit()
				switch c := child.(type) {
				case *VectorCommitmentBranchNode:
					h := sha512.New()
					h.Write([]byte{1})
					for _, p := range c.Prefix {
						h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
					}
					h.Write(out)
					out = h.Sum(nil)
				case *VectorCommitmentLeafNode:
					// do nothing
				}
				data = append(data, out...)
			} else {
				data = append(data, make([]byte, 64)...)
			}
		}

		n.Commitment = rbls48581.CommitRaw(data, 64)
	}

	return n.Commitment
}

func (n *VectorCommitmentBranchNode) Verify(index int, proof []byte) bool {
	data := []byte{}
	if n.Commitment == nil {
		for _, child := range n.Children {
			if child != nil {
				out := child.Commit()
				switch c := child.(type) {
				case *VectorCommitmentBranchNode:
					h := sha512.New()
					h.Write([]byte{1})
					for _, p := range c.Prefix {
						h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
					}
					h.Write(out)
					out = h.Sum(nil)
				case *VectorCommitmentLeafNode:
					// do nothing
				}
				data = append(data, out...)
			} else {
				data = append(data, make([]byte, 64)...)
			}
		}

		n.Commitment = rbls48581.CommitRaw(data, 64)
		data = data[64*index : 64*(index+1)]
	} else {
		child := n.Children[index]
		if child != nil {
			out := child.Commit()
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				// do nothing
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	return rbls48581.VerifyRaw(data, n.Commitment, uint64(index), proof, 64)
}

func (n *VectorCommitmentBranchNode) Prove(index int) []byte {
	data := []byte{}
	for _, child := range n.Children {
		if child != nil {
			out := child.Commit()
			switch c := child.(type) {
			case *VectorCommitmentBranchNode:
				h := sha512.New()
				h.Write([]byte{1})
				for _, p := range c.Prefix {
					h.Write(binary.BigEndian.AppendUint32([]byte{}, uint32(p)))
				}
				h.Write(out)
				out = h.Sum(nil)
			case *VectorCommitmentLeafNode:
				// do nothing
			}
			data = append(data, out...)
		} else {
			data = append(data, make([]byte, 64)...)
		}
	}

	return rbls48581.ProveRaw(data, uint64(index), 64)
}

type VectorCommitmentTree struct {
	Root VectorCommitmentNode
}

// getNextNibble returns the next BranchBits bits from the key starting at pos
func getNextNibble(key []byte, pos int) int {
	startByte := pos / 8
	if startByte >= len(key) {
		return 0
	}

	// Calculate how many bits we need from the current byte
	startBit := pos % 8
	bitsFromCurrentByte := 8 - startBit

	result := int(key[startByte] & ((1 << bitsFromCurrentByte) - 1))

	if bitsFromCurrentByte >= BranchBits {
		// We have enough bits in the current byte
		return (result >> (bitsFromCurrentByte - BranchBits)) & BranchMask
	}

	// We need bits from the next byte
	result = result << (BranchBits - bitsFromCurrentByte)
	if startByte+1 < len(key) {
		remainingBits := BranchBits - bitsFromCurrentByte
		nextByte := int(key[startByte+1])
		result |= (nextByte >> (8 - remainingBits))
	}

	return result & BranchMask
}

func getNibblesUntilDiverge(key1, key2 []byte, startDepth int) ([]int, int) {
	var nibbles []int
	depth := startDepth

	for {
		n1 := getNextNibble(key1, depth)
		n2 := getNextNibble(key2, depth)
		if n1 != n2 {
			return nibbles, depth
		}
		nibbles = append(nibbles, n1)
		depth += BranchBits
	}
}

// getLastNibble returns the final nibble after applying a prefix
func getLastNibble(key []byte, prefixLen int) int {
	return getNextNibble(key, prefixLen*BranchBits)
}

// Insert adds or updates a key-value pair in the tree
func (t *VectorCommitmentTree) Insert(key, value []byte) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	var insert func(node VectorCommitmentNode, depth int) VectorCommitmentNode
	insert = func(node VectorCommitmentNode, depth int) VectorCommitmentNode {
		if node == nil {
			return &VectorCommitmentLeafNode{Key: key, Value: value}
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				n.Value = value
				n.Commitment = nil
				return n
			}

			// Get common prefix nibbles and divergence point
			sharedNibbles, divergeDepth := getNibblesUntilDiverge(n.Key, key, depth)

			// Create single branch node with shared prefix
			branch := &VectorCommitmentBranchNode{
				Prefix: sharedNibbles,
			}

			// Add both leaves at their final positions
			finalOldNibble := getNextNibble(n.Key, divergeDepth)
			finalNewNibble := getNextNibble(key, divergeDepth)
			branch.Children[finalOldNibble] = n
			branch.Children[finalNewNibble] = &VectorCommitmentLeafNode{Key: key, Value: value}

			return branch

		case *VectorCommitmentBranchNode:
			if len(n.Prefix) > 0 {
				// Check if the new key matches the prefix
				for i, expectedNibble := range n.Prefix {
					actualNibble := getNextNibble(key, depth+i*BranchBits)
					if actualNibble != expectedNibble {
						// Create new branch with shared prefix subset
						newBranch := &VectorCommitmentBranchNode{
							Prefix: n.Prefix[:i],
						}
						// Position old branch and new leaf
						newBranch.Children[expectedNibble] = n
						n.Prefix = n.Prefix[i+1:] // remove shared prefix from old branch
						newBranch.Children[actualNibble] = &VectorCommitmentLeafNode{Key: key, Value: value}
						return newBranch
					}
				}
				// Key matches prefix, continue with final nibble
				finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
				n.Children[finalNibble] = insert(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)
				n.Commitment = nil
				return n
			} else {
				// Simple branch without prefix
				nibble := getNextNibble(key, depth)
				n.Children[nibble] = insert(n.Children[nibble], depth+BranchBits)
				n.Commitment = nil
				return n
			}
		}

		return nil
	}

	t.Root = insert(t.Root, 0)
	return nil
}

func (t *VectorCommitmentTree) Verify(key []byte, proofs [][]byte) bool {
	if len(key) == 0 {
		return false
	}

	var verify func(node VectorCommitmentNode, proofs [][]byte, depth int) bool
	verify = func(node VectorCommitmentNode, proofs [][]byte, depth int) bool {
		if node == nil {
			return false
		}

		if len(proofs) == 0 {
			return false
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return bytes.Equal(n.Value, proofs[0])
			}
			return false

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return false
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			if !n.Verify(finalNibble, proofs[0]) {
				return false
			}

			return verify(n.Children[finalNibble], proofs[1:], depth+len(n.Prefix)*BranchBits+BranchBits)
		}

		return false
	}

	return verify(t.Root, proofs, 0)
}

func (t *VectorCommitmentTree) Prove(key []byte) [][]byte {
	if len(key) == 0 {
		return nil
	}

	var prove func(node VectorCommitmentNode, depth int) [][]byte
	prove = func(node VectorCommitmentNode, depth int) [][]byte {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return [][]byte{n.Value}
			}
			return nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil
				}
			}

			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)

			proofs := [][]byte{n.Prove(finalNibble)}

			return append(proofs, prove(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)...)
		}

		return nil
	}

	return prove(t.Root, 0)
}

// Get retrieves a value from the tree by key
func (t *VectorCommitmentTree) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key not allowed")
	}

	var get func(node VectorCommitmentNode, depth int) []byte
	get = func(node VectorCommitmentNode, depth int) []byte {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return n.Value
			}
			return nil

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if getNextNibble(key, depth+i*BranchBits) != expectedNibble {
					return nil
				}
			}
			// Get final nibble after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			return get(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)
		}

		return nil
	}

	value := get(t.Root, 0)
	if value == nil {
		return nil, errors.New("key not found")
	}
	return value, nil
}

// Delete removes a key-value pair from the tree
func (t *VectorCommitmentTree) Delete(key []byte) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	var delete func(node VectorCommitmentNode, depth int) VectorCommitmentNode
	delete = func(node VectorCommitmentNode, depth int) VectorCommitmentNode {
		if node == nil {
			return nil
		}

		switch n := node.(type) {
		case *VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return nil
			}
			return n

		case *VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				currentNibble := getNextNibble(key, depth+i*BranchBits)
				if currentNibble != expectedNibble {
					return n // Key doesn't match prefix, nothing to delete
				}
			}

			// Delete at final position after prefix
			finalNibble := getNextNibble(key, depth+len(n.Prefix)*BranchBits)
			n.Children[finalNibble] = delete(n.Children[finalNibble], depth+len(n.Prefix)*BranchBits+BranchBits)
			n.Commitment = nil

			// Count remaining children
			childCount := 0
			var lastChild VectorCommitmentNode
			var lastIndex int
			for i, child := range n.Children {
				if child != nil {
					childCount++
					lastChild = child
					lastIndex = i
				}
			}

			if childCount == 0 {
				return nil
			} else if childCount == 1 {
				// If the only child is a leaf, keep structure if its path matches
				if leaf, ok := lastChild.(*VectorCommitmentLeafNode); ok {
					if lastIndex == getLastNibble(leaf.Key, len(n.Prefix)) {
						return n
					}
					return leaf
				}
				// If it's a branch, merge the prefixes
				if branch, ok := lastChild.(*VectorCommitmentBranchNode); ok {
					branch.Prefix = append(n.Prefix, branch.Prefix...)
					return branch
				}
			}
			return n
		}

		return nil
	}

	t.Root = delete(t.Root, 0)
	return nil
}

// Commit returns the root of the tree
func (t *VectorCommitmentTree) Commit() []byte {
	if t.Root == nil {
		return make([]byte, 64)
	}
	return t.Root.Commit()
}

func debugNode(node VectorCommitmentNode, depth int, prefix string) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *VectorCommitmentLeafNode:
		fmt.Printf("%sLeaf: key=%x value=%x\n", prefix, n.Key, n.Value)
	case *VectorCommitmentBranchNode:
		fmt.Printf("%sBranch %v:\n", prefix, n.Prefix)
		for i, child := range n.Children {
			if child != nil {
				fmt.Printf("%s  [%d]:\n", prefix, i)
				debugNode(child, depth+1, prefix+"    ")
			}
		}
	}
}
