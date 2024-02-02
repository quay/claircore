package csaf

import (
	"io"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/cve-2021-0084.json")
	if err != nil {
		t.Fatalf("failed to open test data: %v", err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("got an error reading file bytes: %v", err)
	}
	_, err = Parse(b)
	if err != nil {
		t.Fatalf("failed to parse CSAF JSON: %v", err)
	}
}

func TestOpen(t *testing.T) {
	_, err := Open("testdata/cve-2021-0084.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
}

func TestFirstProductName(t *testing.T) {
	c, err := Open("testdata/cve-2021-0084.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}

	fpn := c.FirstProductName()
	if fpn != "red_hat_enterprise_linux_5" {
		t.Fatalf("firstProductName returned %s, expected red_hat_enterprise_linux_5", fpn)
	}
}

func TestFindProductByID(t *testing.T) {
	c, err := Open("testdata/cve-2021-0084.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}

	prod := c.ProductTree.FindProductByID("red_hat_enterprise_linux_9")
	cpe, ok := prod.IdentificationHelper["cpe"]
	if !ok {
		t.Fatal("expecting to find a CPE for red_hat_enterprise_linux_9")
	}
	if cpe != "cpe:/o:redhat:enterprise_linux:9" {
		t.Fatal("expecting to find a CPE cpe:/o:redhat:enterprise_linux:9")
	}
}

func TestListProducts(t *testing.T) {
	c, err := Open("testdata/cve-2021-0084.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
	pl := c.ListProducts()
	if len(pl) != 8 {
		t.Fatalf("found %d products but CSAF document defines 8", len(pl))
	}
}

func TestFindRelationship(t *testing.T) {
	c, err := Open("testdata/cve-2021-0084.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
	rel := c.FindRelationship("red_hat_enterprise_linux_9:kernel", "default_component_of")
	if rel == nil {
		t.Fatal("couldn't find expected relationship")
	}
	if rel.ProductRef != "kernel" {
		t.Fatalf("expecting product_reference kernel, but got %s", rel.ProductRef)
	}
	if rel.RelatesToProductRef != "red_hat_enterprise_linux_9" {
		t.Fatalf("expecting relates_to_product_reference red_hat_enterprise_linux_9, but got %s", rel.RelatesToProductRef)
	}
}

func TestFindRemediation(t *testing.T) {
	c, err := Open("testdata/rhsa-2022-0011.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
	rem := c.FindRemediation("7Server-7.6.AUS:telnet-1:0.17-65.el7_6.src")
	if rem.URL != "https://access.redhat.com/errata/RHSA-2022:0011" {
		t.Fatal("failed to find expected remediation")
	}

	rem = c.FindRemediation("7Server-7.6.AUS:not-existing-1:0.17-65.el7_6.src")
	if rem != nil {
		t.Fatal("expected to find no remediation")
	}
}

func TestFindScore(t *testing.T) {
	c, err := Open("testdata/cve-2024-22047.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
	score := c.FindScore("red_hat_satellite_6:rubygem-audited")
	if score.CVSSV3.VectorString != "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N" {
		t.Fatal("failed to find expected score")
	}
}

func TestFindFirstProductName(t *testing.T) {
	c, err := Open("testdata/rhsa-2022-0011.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
	var firstProductName string
	expectedFirstProductName := "Red Hat Enterprise Linux Server AUS (v. 7.6)"
	for _, branch := range c.ProductTree.Branches {
		firstProductName = branch.FindFirstProductName()
	}
	if firstProductName != expectedFirstProductName {
		t.Fatalf("failed to get first product name, wanted: %s, got: %s", expectedFirstProductName, firstProductName)
	}
}

func TestFindProductIdentifier(t *testing.T) {
	c, err := Open("testdata/rhsa-2022-0011.json")
	if err != nil {
		t.Fatalf("failed to open or parse CSAF JSON: %v", err)
	}
	expectedProductName := "Red Hat Enterprise Linux Server E4S (v. 7.6)"
	product := c.ProductTree.Branches[0].FindProductIdentifier("cpe", "cpe:/o:redhat:rhel_e4s:7.6::server")
	if product == nil {
		t.Fatal("could not find product identifier")
	}
	if product.Name != expectedProductName {
		t.Fatalf("failed to get first product name, wanted: %s, got: %s", expectedProductName, product.Name)
	}
}
