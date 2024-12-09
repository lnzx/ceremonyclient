package tries_test

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	mt "github.com/txaty/go-merkletree"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestPackAndVerifyOutput(t *testing.T) {
	testCases := []struct {
		name      string
		numLeaves int
		modulo    int
		frameNum  uint64
		withPrev  bool
	}{
		{
			name:      "Basic case without previous tree",
			numLeaves: 4,
			modulo:    4,
			frameNum:  1,
			withPrev:  false,
		},
		{
			name:      "With previous tree",
			numLeaves: 8,
			modulo:    8,
			frameNum:  2,
			withPrev:  true,
		},
		{
			name:      "Large tree with previous",
			numLeaves: 16,
			modulo:    16,
			frameNum:  3,
			withPrev:  true,
		},
		{
			name:      "Non-power-of-2 modulo",
			numLeaves: 10,
			modulo:    7,
			frameNum:  4,
			withPrev:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputs := make([]mt.DataBlock, tc.numLeaves)
			for i := range outputs {
				data := make([]byte, 32)
				binary.BigEndian.PutUint32(data, uint32(i))
				outputs[i] = tries.NewProofLeaf(data)
			}

			frame := &protobufs.ClockFrame{
				FrameNumber: tc.frameNum,
				Output:      make([]byte, 516),
			}
			rand.Read(frame.Output)

			var previousTree *mt.MerkleTree
			if tc.withPrev {
				prevOutputs := make([]mt.DataBlock, tc.modulo)
				for i := range prevOutputs {
					data := make([]byte, 32)
					binary.BigEndian.PutUint32(data, uint32(i))
					prevOutputs[i] = tries.NewProofLeaf(data)
				}

				var err error
				previousTree, err = mt.New(
					&mt.Config{
						HashFunc: func(data []byte) ([]byte, error) {
							hash := sha3.Sum256(data)
							return hash[:], nil
						},
						Mode:               mt.ModeProofGen,
						DisableLeafHashing: true,
					},
					prevOutputs,
				)
				require.NoError(t, err)
			}

			tree, output, err := tries.PackOutputIntoPayloadAndProof(
				outputs,
				tc.modulo,
				frame,
				previousTree,
			)
			require.NoError(t, err)
			require.NotNil(t, tree)
			require.NotEmpty(t, output)

			var previousRoot []byte
			if previousTree != nil {
				previousRoot = previousTree.Root
			}

			treeRoot, modulo, frameNumber, verified, err := tries.UnpackAndVerifyOutput(
				previousRoot,
				output,
			)

			require.NoError(t, err)
			require.True(t, verified, "Output verification failed")
			require.Equal(t, tree.Root, treeRoot, "Tree root mismatch")
			require.Equal(t, uint32(tc.modulo), modulo, "Modulo mismatch")
			require.Equal(t, tc.frameNum, frameNumber, "Frame number mismatch")

			if tc.withPrev {
				t.Run("corrupted_proof", func(t *testing.T) {
					corruptedOutput := make([][]byte, len(output))
					copy(corruptedOutput, output)
					if len(corruptedOutput) > 3 {
						corruptedSibling := make([]byte, len(corruptedOutput[3]))
						copy(corruptedSibling, corruptedOutput[3])
						corruptedSibling[0] ^= 0xFF
						corruptedOutput[3] = corruptedSibling
					}

					_, _, _, verified, err := tries.UnpackAndVerifyOutput(
						previousRoot,
						corruptedOutput,
					)
					require.False(t, verified, "Verification should fail with corrupted sibling")
					require.NoError(t, err, "Unexpected error with corrupted sibling")

					corruptedOutput = make([][]byte, len(output))
					copy(corruptedOutput, output)
					if len(corruptedOutput) > 0 {
						lastIdx := len(corruptedOutput) - 1
						corruptedLeaf := make([]byte, len(corruptedOutput[lastIdx]))
						copy(corruptedLeaf, corruptedOutput[lastIdx])
						corruptedLeaf[0] ^= 0xFF
						corruptedOutput[lastIdx] = corruptedLeaf
					}

					_, _, _, verified, err = tries.UnpackAndVerifyOutput(
						previousRoot,
						corruptedOutput,
					)
					require.False(t, verified, "Verification should fail with corrupted leaf")
					require.NoError(t, err, "Unexpected error with corrupted leaf")
				})
			}
		})
	}
}
