package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

type clientTestcase struct {
	Release  Release
	Serve    string
	Expected []string
}

func (tc *clientTestcase) Run(ctx context.Context) func(*testing.T) {
	var err error
	want := make([]*url.URL, len(tc.Expected))
	for i, s := range tc.Expected {
		want[i], err = url.Parse(s)
		if err != nil {
			panic(err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, tc.Serve)
	}))
	client := Client{
		c:       srv.Client(),
		mirrors: make([]*url.URL, 0),
	}

	return func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		t.Cleanup(srv.Close)

		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		err := client.getMirrors(tctx, srv.URL)
		if err != nil {
			t.Error(err)
		}
		t.Log(client.mirrors)
		if got := client.mirrors; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
func TestClientGetMirrors(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	tests := []clientTestcase{
		{
			Release: AmazonLinux1,
			Expected: []string{
				"http://packages.us-west-2.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.us-west-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.us-east-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-southeast-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-northeast-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-northeast-2.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-east-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.eu-west-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.eu-central-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.sa-east-1.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
				"http://packages.ap-southeast-2.amazonaws.com/2018.03/updates/c539f2128d87/x86_64",
			},
			Serve: "testdata/mirrors_linux1.txt",
		},
		{
			Release: AmazonLinux2,
			Expected: []string{
				"https://cdn.amazonlinux.com/2/core/2.0/x86_64/221a4af09d96ac4e34202cc7bdfa252410419542548cc685dc86ed1c17ca4204",
			},
			Serve: "testdata/mirrors_linux2.txt",
		},
		{
			Release: AmazonLinux2023,
			Expected: []string{
				"https://cdn.amazonlinux.com/al2023/core/guids/46ff4933b89b948580f3b223b826fee3c1830b85885db3f7f90502c0ac99698c/x86_64/",
			},
			Serve: "testdata/mirrors_linux2023.txt",
		},
	}

	for _, tc := range tests {
		t.Run(string(tc.Release), tc.Run(ctx))
	}
}
