// Copyright 2019 RedHat
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repomd

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

func Test_Updates_Parse(t *testing.T) {
	path := filepath.Join("testdata", "test_updateinfo.xml")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open test data: %v", err)
	}

	updates := &Updates{}
	err = xml.NewDecoder(f).Decode(updates)
	if err != nil {
		t.Fatalf("failed to parse updateinfo test data into struct: %v", err)
	}

	if got, want := len(updates.Updates), 1170; got != want {
		t.Errorf("unexpected number of updates: got: %d, want: %d", got, want)
	}
}
