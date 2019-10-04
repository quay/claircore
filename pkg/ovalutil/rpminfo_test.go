package ovalutil

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/goval-parser/oval"
)

// TestWalk tests the recursive criterion walker.
func TestWalk(t *testing.T) {
	t.Parallel()

	type testcase struct {
		File  string
		Index int
		Want  []string
	}
	testcases := []testcase{
		{
			File:  "../../oracle/testdata/com.oracle.elsa-2018.xml",
			Index: 199,
			Want: []string{
				`Oracle Linux 7 is installed AND ghostscript is earlier than 0:9.07-31.el7_6.3 AND ghostscript is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-cups is earlier than 0:9.07-31.el7_6.3 AND ghostscript-cups is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-devel is earlier than 0:9.07-31.el7_6.3 AND ghostscript-devel is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-doc is earlier than 0:9.07-31.el7_6.3 AND ghostscript-doc is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-gtk is earlier than 0:9.07-31.el7_6.3 AND ghostscript-gtk is signed with the Oracle Linux 7 key`,
			},
		},
		{
			File:  "../../rhel/testdata/Red_Hat_Enterprise_Linux_3.xml",
			Index: 42,
			Want: []string{
				`Red Hat Enterprise Linux 3 is installed AND samba-common is earlier than 0:3.0.9-1.3E.10 AND samba-common is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 3 is installed AND samba is earlier than 0:3.0.9-1.3E.10 AND samba is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 3 is installed AND samba-swat is earlier than 0:3.0.9-1.3E.10 AND samba-swat is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 3 is installed AND samba-client is earlier than 0:3.0.9-1.3E.10 AND samba-client is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba-common is earlier than 0:3.0.10-1.4E.6.2 AND samba-common is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba-client is earlier than 0:3.0.10-1.4E.6.2 AND samba-client is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba is earlier than 0:3.0.10-1.4E.6.2 AND samba is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba-swat is earlier than 0:3.0.10-1.4E.6.2 AND samba-swat is signed with Red Hat master key`,
			},
		},
		{
			File:  "../../suse/testdata/suse.linux.enterprise.desktop.10.xml",
			Index: 6,
			Want: []string{
				`sled10-sp1-online is installed AND NetworkManager-devel less than 0.6.4-60.26`,
				`sled10-sp1-online is installed AND NetworkManager-glib less than 0.6.4-60.26`,
				`sled10-sp1-online is installed AND NetworkManager-gnome less than 0.6.4-60.26`,
				`sled10-sp1-online is installed AND NetworkManager-openvpn less than 0.3.2cvs20060202-20.25`,
				`sled10-sp1-online is installed AND NetworkManager-vpnc less than 0.5.0cvs20060202-19.30`,
				`sled10-sp1-online is installed AND NetworkManager less than 0.6.4-60.26`,
				`sled10-sp1-online is installed AND art-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND audit-libs-32bit less than 1.2.9-6.9`,
				`sled10-sp1-online is installed AND audit-libs-python less than 1.2.9-12.9`,
				`sled10-sp1-online is installed AND audit-libs less than 1.2.9-6.9`,
				`sled10-sp1-online is installed AND audit less than 1.2.9-6.9`,
				`sled10-sp1-online is installed AND beagle-evolution less than 0.2.16.3-1.13`,
				`sled10-sp1-online is installed AND beagle-firefox less than 0.2.16.3-1.13`,
				`sled10-sp1-online is installed AND beagle-gui less than 0.2.16.3-1.13`,
				`sled10-sp1-online is installed AND beagle less than 0.2.16.3-1.13`,
				`sled10-sp1-online is installed AND cifs-mount less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND compiz less than 0.4.0-0.21`,
				`sled10-sp1-online is installed AND contact-lookup-applet less than 0.13-21.14`,
				`sled10-sp1-online is installed AND dhcp-client less than 3.0.3-23.33`,
				`sled10-sp1-online is installed AND dhcp less than 3.0.3-23.33`,
				`sled10-sp1-online is installed AND dia less than 0.94-41.22`,
				`sled10-sp1-online is installed AND evolution-devel less than 2.6.0-49.55`,
				`sled10-sp1-online is installed AND evolution-exchange less than 2.6.0-27.34`,
				`sled10-sp1-online is installed AND evolution-pilot less than 2.6.0-49.55`,
				`sled10-sp1-online is installed AND evolution-webcal less than 2.4.1-18.14`,
				`sled10-sp1-online is installed AND evolution less than 2.6.0-49.55`,
				`sled10-sp1-online is installed AND f-spot less than 0.3.5-0.16`,
				`sled10-sp1-online is installed AND gaim-devel less than 1.5.0-50.17`,
				`sled10-sp1-online is installed AND gaim less than 1.5.0-50.17`,
				`sled10-sp1-online is installed AND gconf-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gda-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gdb less than 6.6-12.20`,
				`sled10-sp1-online is installed AND gftp less than 2.0.18-25.15`,
				`sled10-sp1-online is installed AND glade-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND glib-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND glib2-32bit less than 2.8.6-0.8`,
				`sled10-sp1-online is installed AND glib2-devel less than 2.8.6-0.8`,
				`sled10-sp1-online is installed AND glib2-doc less than 2.8.6-0.8`,
				`sled10-sp1-online is installed AND glib2 less than 2.8.6-0.8`,
				`sled10-sp1-online is installed AND gnome-backgrounds less than 2.12.3.1-0.8`,
				`sled10-sp1-online is installed AND gnome-filesystem less than 0.1-261.12`,
				`sled10-sp1-online is installed AND gnome-games less than 2.12.3-0.12`,
				`sled10-sp1-online is installed AND gnome-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gnomedb-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gnopernicus-devel less than 1.0.0-23.14`,
				`sled10-sp1-online is installed AND gnopernicus less than 1.0.0-23.14`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-32bit less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-devel less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-doc less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-oil-32bit less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-oil less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-visual-32bit less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base-visual less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gstreamer010-plugins-base less than 0.10.5-11.17`,
				`sled10-sp1-online is installed AND gtk-sharp-32bit less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gtk-sharp-complete less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gtk-sharp-gapi less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gtk-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND gtkhtml-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND helix-dbus-server less than 0.4.0-0.10`,
				`sled10-sp1-online is installed AND inkscape less than 0.43-20.15`,
				`sled10-sp1-online is installed AND libbeagle-32bit less than 0.2.16.3-1.12`,
				`sled10-sp1-online is installed AND libbeagle-devel less than 0.2.16.3-1.12`,
				`sled10-sp1-online is installed AND libbeagle less than 0.2.16.3-1.12`,
				`sled10-sp1-online is installed AND libgail-gnome-devel less than 1.1.3-41.13`,
				`sled10-sp1-online is installed AND libgail-gnome less than 1.1.3-41.13`,
				`sled10-sp1-online is installed AND libgdiplus less than 1.2.2-13.13`,
				`sled10-sp1-online is installed AND libipoddevice-32bit less than 0.5.2-1.17`,
				`sled10-sp1-online is installed AND libipoddevice less than 0.5.2-1.17`,
				`sled10-sp1-online is installed AND libsmbclient-32bit less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND libsmbclient-devel less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND libsmbclient less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND libtool-32bit less than 1.5.22-13.12`,
				`sled10-sp1-online is installed AND libtool less than 1.5.22-13.12`,
				`sled10-sp1-online is installed AND linphone-applet less than 1.2.0-16.14`,
				`sled10-sp1-online is installed AND linphone less than 1.2.0-16.14`,
				`sled10-sp1-online is installed AND openobex-devel less than 1.3-28.7`,
				`sled10-sp1-online is installed AND openobex less than 1.3-28.7`,
				`sled10-sp1-online is installed AND planner-devel less than 0.14.1-24.12`,
				`sled10-sp1-online is installed AND planner less than 0.14.1-24.12`,
				`sled10-sp1-online is installed AND pwlib-devel less than 1.10.4-0.10`,
				`sled10-sp1-online is installed AND pwlib less than 1.10.4-0.10`,
				`sled10-sp1-online is installed AND resapplet less than 0.1.4-5.20`,
				`sled10-sp1-online is installed AND rsvg-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND sabayon-admin less than 2.12.3-21.29`,
				`sled10-sp1-online is installed AND sabayon less than 2.12.3-21.29`,
				`sled10-sp1-online is installed AND samba-32bit less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-client-32bit less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-client less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-doc less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-krb-printing less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-pdb less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-vscan less than 0.3.6b-42.49`,
				`sled10-sp1-online is installed AND samba-winbind-32bit less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba-winbind less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND samba less than 3.0.24-2.23`,
				`sled10-sp1-online is installed AND tomboy less than 0.6.0-0.21`,
				`sled10-sp1-online is installed AND vte-sharp less than 1.0.10-30.15`,
				`sled10-sp1-online is installed AND wbxml2 less than 0.9.0-18.10`,
				`sled10-sp1-online is installed AND xgl-hardware-list less than 070326-0.5`,
				`sled10-sp1-online is installed AND xgl less than cvs_060522-0.32`,
			},
		},
	}

	runtest := func(c testcase) func(*testing.T) {
		// Must be the value, because of how ranges work, remember.
		return func(t *testing.T) {
			t.Parallel()

			// First, go open up the file and de-xml it.
			f, err := os.Open(c.File)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var root oval.Root
			if err := xml.NewDecoder(f).Decode(&root); err != nil {
				t.Error(err)
			}
			defs := root.Definitions.Definitions
			if len(defs) < c.Index {
				t.Fatalf("len(defs) = %d, less than %d", len(defs), c.Index)
			}
			defer func() {
				if t.Failed() {
					t.Logf("definition: %#+v", &defs[c.Index])
				}
			}()

			// Then, do the walk.
			cr, err := walk(&defs[c.Index].Criteria)
			if err != nil {
				t.Fatal(err)
			}
			// And make some pretty strings.
			got := make([]string, len(cr))
			for i, cs := range cr {
				b := strings.Builder{}
				for i, c := range cs {
					if i != 0 {
						b.WriteString(" AND ")
					}
					b.WriteString(c.Comment)
				}
				got[i] = b.String()
				t.Log(b.String())
			}

			// Finally, compare our pretty strings.
			if got, want := len(got), len(c.Want); got != want {
				t.Errorf("got: len(got) == %d, want: len(got) == %d", got, want)
			}
			for i := range c.Want {
				if i == len(got) {
					break
				}
				if got, want := got[i], c.Want[i]; got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
			}
		}
	}

	for _, c := range testcases {
		t.Run(filepath.Base(c.File), runtest(c))
	}
}
