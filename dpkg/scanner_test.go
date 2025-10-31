package dpkg

import (
	"archive/tar"
	"bufio"
	"errors"
	"io"
	"net/textproto"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestScanner(t *testing.T) {
	t.Parallel()
	// TODO(hank) Cook up a manifest format for dpkg ala `test/rpmtest.Manifest`
	want := []*claircore.Package{
		{
			Name:           "fdisk",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "9debc95b96eed7df33817e62654b7649",
		},
		{
			Name:           "libpam-runtime",
			Version:        "1.1.8-3.6ubuntu2.18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "pam", Version: "1.1.8-3.6ubuntu2.18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "f96da69e0bd2f91f257c09522e2e48a9",
		},
		{
			Name:           "libncurses5",
			Version:        "6.1-1ubuntu1.18.04",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "ncurses", Version: "6.1-1ubuntu1.18.04", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "9d18792b91935a5849328cb368005ec9",
		},
		{
			Name:           "libcom-err2",
			Version:        "1.44.1-1ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "e2fsprogs", Version: "1.44.1-1ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "6ed12cf8b536fa9eca59fd8b0e544111",
		},
		{
			Name:           "libapt-pkg5.0",
			Version:        "1.6.11",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "apt", Version: "1.6.11", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "b0e3976b91845036e35cbfb01ec6d6eb",
		},
		{
			Name:           "libaudit1",
			Version:        "1:2.8.2-1ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "audit", Version: "1:2.8.2-1ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "5c0000030cfa810d6c835ab82f517ee6",
		},
		{
			Name:           "libtinfo5",
			Version:        "6.1-1ubuntu1.18.04",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "ncurses", Version: "6.1-1ubuntu1.18.04", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "33ca525ace7a21d05093465f64207cca",
		},
		{
			Name:           "perl-base",
			Version:        "5.26.1-6ubuntu0.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "perl", Version: "5.26.1-6ubuntu0.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "f17ad9208249962b7a52349494ce75ff",
		},
		{
			Name:           "libudev1",
			Version:        "237-3ubuntu10.25",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "systemd", Version: "237-3ubuntu10.25", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "a6216ccf2388067c734fb7f568f3e0a8",
		},
		{
			Name:           "libunistring2",
			Version:        "0.9.9-0ubuntu2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libunistring", Version: "0.9.9-0ubuntu2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "db7af6bc39ecfe032ce4e7a6f858259d",
		},
		{
			Name:           "libnettle6",
			Version:        "3.4-1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "nettle", Version: "3.4-1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "02bfb40df3039b604a89a846e5daf10c",
		},
		{
			Name:           "libattr1",
			Version:        "1:2.4.47-2build1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "attr", Version: "1:2.4.47-2build1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "a915a7ea4dd5f10d4d4d385d2c24192d",
		},
		{
			Name:           "libss2",
			Version:        "1.44.1-1ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "e2fsprogs", Version: "1.44.1-1ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "06ebd35af75313d7ce587f6d83720209",
		},
		{
			Name:           "liblzma5",
			Version:        "5.2.2-1.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "xz-utils", Version: "5.2.2-1.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "16e9fc306ca68a3a7806754784b52d8c",
		},
		{
			Name:           "libidn2-0",
			Version:        "2.0.4-1.1build2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libidn2", Version: "2.0.4-1.1build2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "ebecbbce67182ce137f5ca10ed2122e4",
		},
		{
			Name:           "libpam-modules-bin",
			Version:        "1.1.8-3.6ubuntu2.18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "pam", Version: "1.1.8-3.6ubuntu2.18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "7b7262bc55945a4b9dfc5bb3a4125974",
		},
		{
			Name:           "grep",
			Version:        "3.1-2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "grep", Version: "3.1-2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4455aef7b04af0c9ce1cf2aa6129fed7",
		},
		{
			Name:           "base-passwd",
			Version:        "3.5.44",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "base-passwd", Version: "3.5.44", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "302889f7be244dc6664821cdba719b6e",
		},
		{
			Name:           "liblz4-1",
			Version:        "0.0~r131-2ubuntu3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "lz4", Version: "0.0~r131-2ubuntu3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "2c4983fb7dd0ba7e990ff7661a3f2379",
		},
		{
			Name:           "debianutils",
			Version:        "4.8.4",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "debianutils", Version: "4.8.4", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "e4235d987575ef2b67b99113b311f5b6",
		},
		{
			Name:           "libgcrypt20",
			Version:        "1.8.1-4ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libgcrypt20", Version: "1.8.1-4ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "217a9e55d627ef5e638296a0ad54a4fd",
		},
		{
			Name:           "libncursesw5",
			Version:        "6.1-1ubuntu1.18.04",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "ncurses", Version: "6.1-1ubuntu1.18.04", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "14164ca584dfc5968d2f00cced8e9dd7",
		},
		{
			Name:           "bash",
			Version:        "4.4.18-2ubuntu1.2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "bash", Version: "4.4.18-2ubuntu1.2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "bc32b6211b320538050b775f28daa2a1",
		},
		{
			Name:           "libuuid1",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "056a0822246369948a91cdebbb295225",
		},
		{
			Name:           "libdb5.3",
			Version:        "5.3.28-13.1ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "db5.3", Version: "5.3.28-13.1ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "d81a5051ae0295d8ec791e8592849b8e",
		},
		{
			Name:           "debconf",
			Version:        "1.5.66ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "debconf", Version: "1.5.66ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "f3217960643ae75cc292e59488aabae2",
		},
		{
			Name:           "zlib1g",
			Version:        "1:1.2.11.dfsg-0ubuntu2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "zlib", Version: "1:1.2.11.dfsg-0ubuntu2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "3270b12c3a9a6ee9f4ae27ffeb407a6c",
		},
		{
			Name:           "hostname",
			Version:        "3.20",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "hostname", Version: "3.20", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "6e0f038548ebd196e0659b06fe81a466",
		},
		{
			Name:           "mawk",
			Version:        "1.3.3-17ubuntu3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "mawk", Version: "1.3.3-17ubuntu3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4e377c681d072a697175326a3fcd14da",
		},
		{
			Name:           "gzip",
			Version:        "1.6-5ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gzip", Version: "1.6-5ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "762f8b7616e78c56ef2c6345361ec179",
		},
		{
			Name:           "gpgv",
			Version:        "2.2.4-1ubuntu1.2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gnupg2", Version: "2.2.4-1ubuntu1.2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4ff938019bf794bd82c6306a04597855",
		},
		{
			Name:           "bsdutils",
			Version:        "1:2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "944a8ca185896c4fc8e6d403c44c089f",
		},
		{
			Name:           "dash",
			Version:        "0.5.8-2.10",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "dash", Version: "0.5.8-2.10", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "5267d9451e76c53a4a6dd49a7abf3d0a",
		},
		{
			Name:           "mount",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "81cd4e0dabde7615af9fbf50c251f034",
		},
		{
			Name:           "libgnutls30",
			Version:        "3.5.18-1ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gnutls28", Version: "3.5.18-1ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "3ded475856db7dde94c0fd8f5300480a",
		},
		{
			Name:           "libsystemd0",
			Version:        "237-3ubuntu10.25",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "systemd", Version: "237-3ubuntu10.25", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "c809acd40a40b37b55491cdb4bd69fb2",
		},
		{
			Name:           "libzstd1",
			Version:        "1.3.3+dfsg-2ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libzstd", Version: "1.3.3+dfsg-2ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "753d597807e707445ac96a84de2fc62a",
		},
		{
			Name:           "libc6",
			Version:        "2.27-3ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "glibc", Version: "2.27-3ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "69b26e314836bc5fc6364b99b6656f20",
		},
		{
			Name:           "libfdisk1",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "ba4b64c92f8c2d133390d30a86dd75b7",
		},
		{
			Name:           "libpcre3",
			Version:        "2:8.39-9",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "pcre3", Version: "2:8.39-9", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "56b9cf5dd90f5da6b904b2b90f2a757d",
		},
		{
			Name:           "coreutils",
			Version:        "8.28-1ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "coreutils", Version: "8.28-1ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "c39a8196b07f782ffeea8909a36af21a",
		},
		{
			Name:           "e2fsprogs",
			Version:        "1.44.1-1ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "e2fsprogs", Version: "1.44.1-1ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "15e1f965b09cd8b51d75001e7c043ae0",
		},
		{
			Name:           "tar",
			Version:        "1.29b-2ubuntu0.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "tar", Version: "1.29b-2ubuntu0.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "e403332f4aee4679e817acaa5d0809eb",
		},
		{
			Name:           "libprocps6",
			Version:        "2:3.3.12-3ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "procps", Version: "2:3.3.12-3ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "1dfb5da1f9e5b56b91557cf3d0fadc17",
		},
		{
			Name:           "libbz2-1.0",
			Version:        "1.0.6-8.1ubuntu0.2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "bzip2", Version: "1.0.6-8.1ubuntu0.2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4c94d04d3bd207d6c66b0275467a3434",
		},
		{
			Name:           "libblkid1",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "002355d5a4c210677b484b88ee906711",
		},
		{
			Name:           "libtasn1-6",
			Version:        "4.13-2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libtasn1-6", Version: "4.13-2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "40833fb62f189ad0b699085f37fa126b",
		},
		{
			Name:           "bzip2",
			Version:        "1.0.6-8.1ubuntu0.2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "bzip2", Version: "1.0.6-8.1ubuntu0.2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "7870caea30545bd4fc8470cd7c71cee5",
		},
		{
			Name:           "libhogweed4",
			Version:        "3.4-1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "nettle", Version: "3.4-1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "7d676949637c18ec15c784d9e0f0d2b7",
		},
		{
			Name:           "lsb-base",
			Version:        "9.20170808ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "lsb", Version: "9.20170808ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "81f59c0711532f60f4bba8cff2bdc194",
		},
		{
			Name:           "procps",
			Version:        "2:3.3.12-3ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "procps", Version: "2:3.3.12-3ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "6226ab16fc27c981a04e5236cd357db4",
		},
		{
			Name:           "libgpg-error0",
			Version:        "1.27-6",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libgpg-error", Version: "1.27-6", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "9ac0b2bb54b5fca41b5699ab285fd537",
		},
		{
			Name:           "base-files",
			Version:        "10.1ubuntu2.6",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "base-files", Version: "10.1ubuntu2.6", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "b7adc247e1bbd04d0fa877ad976e6999",
		},
		{
			Name:           "libgmp10",
			Version:        "2:6.1.2+dfsg-2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gmp", Version: "2:6.1.2+dfsg-2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "0582a99d7e1af42e4e467f8bfb3eefb2",
		},
		{
			Name:           "sensible-utils",
			Version:        "0.0.12",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "sensible-utils", Version: "0.0.12", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "acacef732b02d7b18bc55fb076129e97",
		},
		{
			Name:           "passwd",
			Version:        "1:4.5-1ubuntu2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "shadow", Version: "1:4.5-1ubuntu2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "b07c719065496584ffc5d22aad31bd26",
		},
		{
			Name:           "init-system-helpers",
			Version:        "1.51",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "init-system-helpers", Version: "1.51", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "12ce455753af8d952171bcd97fd9ae46",
		},
		{
			Name:           "ncurses-base",
			Version:        "6.1-1ubuntu1.18.04",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "ncurses", Version: "6.1-1ubuntu1.18.04", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "82f72407e909caaa18dbc13a5d8dcec4",
		},
		{
			Name:           "libc-bin",
			Version:        "2.27-3ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "glibc", Version: "2.27-3ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "6a8dfc87afeac7c23a876c771153203c",
		},
		{
			Name:           "libsemanage1",
			Version:        "2.7-2build2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libsemanage", Version: "2.7-2build2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "2213290d7f16a01ea80c776b161c4d4b",
		},
		{
			Name:           "libseccomp2",
			Version:        "2.4.1-0ubuntu0.18.04.2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libseccomp", Version: "2.4.1-0ubuntu0.18.04.2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "6a2c4bd25b02d438edc8b955a190c182",
		},
		{
			Name:           "sysvinit-utils",
			Version:        "2.88dsf-59.10ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "sysvinit", Version: "2.88dsf-59.10ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4df656cc5c9bf0083c342c8bd294c28e",
		},
		{
			Name:           "libsemanage-common",
			Version:        "2.7-2build2",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "libsemanage", Version: "2.7-2build2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "d39631bf96b2162fdc3a53291a39df62",
		},
		{
			Name:           "libp11-kit0",
			Version:        "0.23.9-2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "p11-kit", Version: "0.23.9-2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "61f2a011afb14b04083002d28cb94b9e",
		},
		{
			Name:           "libdebconfclient0",
			Version:        "0.213ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "cdebconf", Version: "0.213ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "8a28204a765d5720cb4af1753f45bed7",
		},
		{
			Name:           "libselinux1",
			Version:        "2.7-2build2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libselinux", Version: "2.7-2build2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "a2f847fab267ff4cc6f08351c5d72e16",
		},
		{
			Name:           "dpkg",
			Version:        "1.19.0.5ubuntu2.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "dpkg", Version: "1.19.0.5ubuntu2.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "db01a1c0f91bf54aa1126ae814a48760",
		},
		{
			Name:           "gcc-8-base",
			Version:        "8.3.0-6ubuntu1~18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gcc-8", Version: "8.3.0-6ubuntu1~18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "7dac2f53b10d468727cfd34dfe5fdaf7",
		},
		{
			Name:           "apt",
			Version:        "1.6.11",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "apt", Version: "1.6.11", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "bc3018653614f09a74c49875673b4e35",
		},
		{
			Name:           "diffutils",
			Version:        "1:3.6-1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "diffutils", Version: "1:3.6-1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "49ed959780dcc73b86202dff1614518d",
		},
		{
			Name:           "libpam-modules",
			Version:        "1.1.8-3.6ubuntu2.18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "pam", Version: "1.1.8-3.6ubuntu2.18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "d26dab685afef1e59fdf6eea227a764f",
		},
		{
			Name:           "libstdc++6",
			Version:        "8.3.0-6ubuntu1~18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gcc-8", Version: "8.3.0-6ubuntu1~18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "67d777333913485c1776d89fe0be2265",
		},
		{
			Name:           "libffi6",
			Version:        "3.2.1-8",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libffi", Version: "3.2.1-8", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "c98a2d5689d41ff8c9d7fa0b8053fd35",
		},
		{
			Name:           "libaudit-common",
			Version:        "1:2.8.2-1ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "audit", Version: "1:2.8.2-1ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "96dff9fbe852eedc8324c4c659c6c9fb",
		},
		{
			Name:           "findutils",
			Version:        "4.6.0+git+20170828-2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "findutils", Version: "4.6.0+git+20170828-2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "a69359638ce4239976bc4d2902fd422e",
		},
		{
			Name:           "libpam0g",
			Version:        "1.1.8-3.6ubuntu2.18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "pam", Version: "1.1.8-3.6ubuntu2.18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "2b70bcd8348ded4048eb05371d206057",
		},
		{
			Name:           "libcap-ng0",
			Version:        "0.7.7-3.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libcap-ng", Version: "0.7.7-3.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "eef5c8b83a5c83ac1d800421013c35d4",
		},
		{
			Name:           "libmount1",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "54de57abe4e728e553aa9bb3c0a3486b",
		},
		{
			Name:           "login",
			Version:        "1:4.5-1ubuntu2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "shadow", Version: "1:4.5-1ubuntu2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "fb7eb3beb226312b5fc206b9b68196e4",
		},
		{
			Name:           "adduser",
			Version:        "3.116ubuntu1",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "adduser", Version: "3.116ubuntu1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "695a46afe8d2418119a6c814272624b2",
		},
		{
			Name:           "libext2fs2",
			Version:        "1.44.1-1ubuntu1.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "e2fsprogs", Version: "1.44.1-1ubuntu1.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "b1b278bfc418d3ded83ce0fa811c1b72",
		},
		{
			Name:           "libacl1",
			Version:        "2.2.52-3build1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "acl", Version: "2.2.52-3build1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4eb315544d7022817f09883f271f3838",
		},
		{
			Name:           "ncurses-bin",
			Version:        "6.1-1ubuntu1.18.04",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "ncurses", Version: "6.1-1ubuntu1.18.04", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "87fcc071cfb913ef124a557295cfe91f",
		},
		{
			Name:           "libsepol1",
			Version:        "2.7-1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "libsepol", Version: "2.7-1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "969d98356cf0185d41fcb360b3cc78f0",
		},
		{
			Name:           "ubuntu-keyring",
			Version:        "2018.09.18.1~18.04.0",
			Kind:           claircore.BINARY,
			Arch:           "all",
			Source:         &claircore.Package{Name: "ubuntu-keyring", Version: "2018.09.18.1~18.04.0", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "6670fc17c7bfbf2f394e994c2324809a",
		},
		{
			Name:           "libgcc1",
			Version:        "1:8.3.0-6ubuntu1~18.04.1",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "gcc-8", Version: "8.3.0-6ubuntu1~18.04.1", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "9bccc3f84c1c9038a55c211f84014a65",
		},
		{
			Name:           "util-linux",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "4fedd5fb77f729d76705cc545e983730",
		},
		{
			Name:           "sed",
			Version:        "4.4-2",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "sed", Version: "4.4-2", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "bf8c924cef13e42a861f3297ac32ce49",
		},
		{
			Name:           "libsmartcols1",
			Version:        "2.31.1-0.4ubuntu3.3",
			Kind:           claircore.BINARY,
			Arch:           "amd64",
			Source:         &claircore.Package{Name: "util-linux", Version: "2.31.1-0.4ubuntu3.3", Kind: claircore.SOURCE, PackageDB: "var/lib/dpkg/status"},
			PackageDB:      "var/lib/dpkg/status",
			RepositoryHint: "daafc6eba6eae603327bf8fc49645999",
		},
	}
	slices.SortFunc(want, sortpkg)
	ctx := test.Logging(t)
	l := test.RealizeLayer(ctx, t, test.LayerRef{
		Registry: "docker.io",
		Name:     "library/ubuntu",
		Digest:   "sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a",
	})
	var s Scanner

	got, err := s.Scan(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Equal(got, want) {
		t.Fatal(cmp.Diff(got, want))
	}
}

func TestExtraMetadata(t *testing.T) {
	t.Parallel()
	mod := test.Modtime(t, "scanner_test.go")
	layerfile := test.GenerateFixture(t, `extrametadata.layer`, mod, extraMetadataSetup)
	ctx := test.Logging(t)
	var l claircore.Layer
	var s Scanner

	f, err := os.Open(layerfile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := l.Init(ctx, &test.AnyDescription, f); err != nil {
		t.Error(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})

	ps, err := s.Scan(ctx, &l)
	if err != nil {
		t.Error(err)
	}
	if got, want := len(ps), 1; got != want {
		t.Errorf("checking length, got: %d, want: %d", got, want)
	}
}

// ExtraMetadataSetup is a helper to craft a layer that trips PROJQUAY-1308.
func extraMetadataSetup(t testing.TB, f *os.File) {
	w := tar.NewWriter(f)
	defer func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, n := range []string{
		"db/",
		"db/available",
		"db/info.md5sums",
		"db/info/",
		"db/info/bogus.md5sums",
		"db/info/extra.md5sums",
	} {
		if err := w.WriteHeader(&tar.Header{
			Name: n,
		}); err != nil {
			t.Error(err)
		}
	}
	const statusfile = `Package: bogus
Status: install ok installed
Priority: important
Section: admin
Installed-Size: 0
Maintainer: Veryreal Developer <email@example.com>
Architecture: all
Version: 1

`
	if err := w.WriteHeader(&tar.Header{
		Name: "db/status",
		Size: int64(len(statusfile)),
	}); err != nil {
		t.Error(err)
	}
	if _, err := io.WriteString(w, statusfile); err != nil {
		t.Error(err)
	}
}

// This is a giant status file because texlive was installed.
func TestGiantStatus(t *testing.T) {
	t.Parallel()
	db, err := os.Open(`testdata/texlive.status`)
	if err != nil {
		t.Fatal(err)
	}

	var found int
	tp := textproto.NewReader(bufio.NewReader(db))
	hdr, err := tp.ReadMIMEHeader()
	for ; err == nil && len(hdr) > 0; hdr, err = tp.ReadMIMEHeader() {
		found++
	}
	t.Logf("found %d installed packages", found)
	if got, want := found, 357; got != want {
		t.Fail()
	}
	if err != nil && err != io.EOF {
		t.Error(err)
	}
}

// See quay/claircore#297 for more context.
func TestKeyringPackage(t *testing.T) {
	t.Parallel()
	db, err := os.Open(`testdata/debian-only.status`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tp := textproto.NewReader(bufio.NewReader(db))
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		t.Error(err)
	}
	got, want := hdr.Get("Version"), `2019.1`
	t.Logf("got: %q, want: %q", got, want)
	if got != want {
		t.Fail()
	}
}

// See quay/claircore#1291 for more context.
func TestParsedSource(t *testing.T) {
	t.Parallel()
	const filename = `testdata/postgresql.status`
	ctx := test.Logging(t)

	db, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	found := newPackages()
	tp := textproto.NewReader(bufio.NewReader(db))

	if err := parseStatus(ctx, found, filename, tp); err != nil {
		t.Error(err)
	}

	pkg, ok := found.bin["postgresql-client"]
	if !ok {
		t.Fatalf("unable to find package %q", "postgresql-client")
	}
	src := pkg.Source
	got, want := src.Name, "postgresql-common"
	t.Logf("got: %q, want: %q", got, want)
	if got != want {
		t.Fail()
	}
	got, want = src.Version, "200+deb10u5"
	t.Logf("got: %q, want: %q", got, want)
	if got != want {
		t.Fail()
	}
}

// See quay/claircore#1359
func TestNotDB(t *testing.T) {
	t.Parallel()
	const filename = `testdata/vcpkg.status`
	ctx := test.Logging(t)

	db, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	found := newPackages()
	tp := textproto.NewReader(bufio.NewReader(db))

	got := parseStatus(ctx, found, filename, tp)
	t.Logf("got: %v", got)
	if want := errNotDpkgDB; !errors.Is(got, want) {
		t.Logf("want: %v", want)
		t.Fail()
	}
}
