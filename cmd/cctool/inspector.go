package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/quay/claircore"
)

// Inspect calls external commands to inspect the specified image.
//
// The command (skopeo or docker) needs to be configured with any needed
// permissions.
func Inspect(ctx context.Context, image string, useDocker bool) (*claircore.Manifest, error) {
	cmdbuf := bytes.Buffer{}
	cmd := exec.CommandContext(ctx, "skopeo", "inspect", image)
	if useDocker {
		image = strings.TrimPrefix(`docker://`, image)
		cmd = exec.CommandContext(ctx, "docker", "manifest", "inspect", image)
	}
	cmd.Stdout = &cmdbuf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var j skopeoJSON
	if err := json.NewDecoder(&cmdbuf).Decode(&j); err != nil {
		return nil, err
	}
	m := claircore.Manifest{
		Hash:   strings.TrimPrefix(j.Digest, "sha256:"),
		Layers: make([]*claircore.Layer, len(j.Layers)),
	}
	for i, l := range j.Layers {
		m.Layers[i] = &claircore.Layer{
			Hash: strings.TrimPrefix(l, "sha256:"),
		}
	}

	return &m, nil
}

type skopeoJSON struct {
	Digest string
	Layers []string
}
