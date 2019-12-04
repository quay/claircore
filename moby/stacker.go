package moby

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	mobyarchive "github.com/moby/moby/pkg/archive"

	"github.com/quay/claircore"
)

// Stacker should take a list of *claircore.Layer structs and stacks their contents
// in the same way a container runtime would. once stacked the "image" layer should be
// returned
type Stacker interface {
	Stack(manifestHash string, layers []*claircore.Layer) (*claircore.Layer, error)
}

// stacker implements the Stacker interface
type stacker struct {
}

func NewStacker() Stacker {
	return &stacker{}
}

func (s *stacker) Stack(manifestHash string, layers []*claircore.Layer) (*claircore.Layer, error) {
	// first unpack layer[0] to the filesystem.
	tmpDir, err := s.unpackBaseLayer(manifestHash, layers[0])
	if err != nil {
		return nil, err
	}

	// apply layers 1...n ontop of the unpacked base layer
	err = s.applyLayers(manifestHash, tmpDir, layers[1:])
	if err != nil {
		return nil, err
	}

	imageLayer, err := s.tarImageLayer(manifestHash, tmpDir)

	return imageLayer, nil
}

// unpackBaseLayer takes the base layer of the image's layer set and unpacks it
// to a temporary directory. returns the temp directory name
func (s *stacker) unpackBaseLayer(manifestHash string, layer *claircore.Layer) (string, error) {
	tmpDir, err := ioutil.TempDir("", manifestHash)
	if err != nil {
		return "", fmt.Errorf("could not create tmp directory to unpack layers for manifest %v: %v", manifestHash, err)
	}

	// determine where the layer contents are
	var reader io.Reader
	switch {
	case len(layer.Bytes) > 0:
		reader = bytes.NewReader(layer.Bytes)
	case layer.LocalPath != "":
		fd, err := os.Open(layer.LocalPath)
		if err != nil {
			fmt.Errorf("failed to open base layer contents at %s for manifest %v layer %v: %v", layer.LocalPath, manifestHash, layer.Hash, err)
		}
		defer fd.Close()
		reader = fd
	default:
		return "", fmt.Errorf("could not determine where base layer contents exist")
	}

	// unpack the layers into the temp dir
	_, err = mobyarchive.UnpackLayer(tmpDir, reader, &mobyarchive.TarOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to unpackage base layer for manifest %v: %v", manifestHash, err)
	}

	return tmpDir, nil
}

// applyLayers takes layers 1...n and stacks them ontop of the base layer unpacked at the temp directory
// created in the unpackBaseLayer call.
func (s *stacker) applyLayers(manifestHash string, tmpDir string, layers []*claircore.Layer) error {
	for _, layer := range layers {
		bReader := bytes.NewReader(layer.Bytes)
		_, err := mobyarchive.ApplyUncompressedLayer(tmpDir, bReader, &mobyarchive.TarOptions{})
		if err != nil {
			return fmt.Errorf("failed to apply layer %v for manifest %v: %v", layer.Hash, manifestHash, err)
		}
	}

	return nil
}

func (s *stacker) tarImageLayer(manifestHash string, tmpDir string) (*claircore.Layer, error) {
	// create a synthetic image layer named with the manifest hash
	imageLayer := &claircore.Layer{
		Hash:   manifestHash,
		Format: "tar",
	}

	// tar the current tmp directory
	tar, err := mobyarchive.TarWithOptions(tmpDir, &mobyarchive.TarOptions{
		Compression: mobyarchive.Uncompressed})
	if err != nil {
		return nil, fmt.Errorf("failed to tar image directory: %v", err)
	}

	// copy tar'd contents into layer bytes and add to layer's byte array
	tarBuf := bytes.NewBuffer([]byte{})
	_, err = io.Copy(tarBuf, tar)
	if err != nil {
		return nil, fmt.Errorf("failed to copy tar into layer's Bytes field: %v", err)
	}

	imageLayer.Bytes = tarBuf.Bytes()

	return imageLayer, nil
}
