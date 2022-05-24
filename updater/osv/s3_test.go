package osv

import (
	"encoding/xml"
	"os"
	"testing"
)

func TestXML(t *testing.T) {
	f, err := os.Open("testdata/list.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var res listBucketResult
	res.Contents = make([]contents, 0, 1000)
	if err := xml.NewDecoder(f).Decode(&res); err != nil {
		t.Error(err)
	}

	if got, want := len(res.Contents), 1000; got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
}
