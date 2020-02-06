package main

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/quay/claircore"
)

// Inspect calls external commands to inspect the specified image.
//
// The command (skopeo or docker) needs to be configured with any needed
// permissions.
func Inspect(ctx context.Context, r string) (*claircore.Manifest, error) {
	ref, err := name.ParseReference(r)
	if err != nil {
		return nil, err
	}
	repo := ref.Context()
	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return nil, err
	}
	rt, err := transport.New(repo.Registry, auth, http.DefaultTransport, []string{repo.Scope("pull")})
	if err != nil {
		return nil, err
	}

	desc, err := remote.Get(ref, remote.WithTransport(rt))
	if err != nil {
		return nil, err
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}

	h, err := img.Digest()
	if err != nil {
		return nil, err
	}
	ccd, err := claircore.ParseDigest(h.String())
	if err != nil {
		return nil, err
	}
	out := claircore.Manifest{
		Hash: ccd,
	}

	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}

	rURL := url.URL{
		Scheme: repo.Scheme(),
		Host:   repo.RegistryStr(),
	}
	c := http.Client{
		Transport: rt,
	}

	for _, l := range ls {
		d, err := l.Digest()
		if err != nil {
			return nil, err
		}
		ccd, err := claircore.ParseDigest(d.String())
		if err != nil {
			return nil, err
		}
		u, err := rURL.Parse(path.Join("/", "v2", strings.TrimPrefix(repo.RepositoryStr(), repo.RegistryStr()), "blobs", d.String()))
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
		if err != nil {
			return nil, err
		}
		res, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		res.Body.Close()

		res.Request.Header.Del("User-Agent")
		out.Layers = append(out.Layers, &claircore.Layer{
			Hash:    ccd,
			URI:     res.Request.URL.String(),
			Headers: res.Request.Header,
		})
	}

	return &out, nil
}
