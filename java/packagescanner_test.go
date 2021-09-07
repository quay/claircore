package java_test

import (
	"context"
	"path"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/java"
	"github.com/quay/claircore/test"
)

// TestScan runs the java scanner over some layers known to have java
// packages installed.
func TestScan(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	for _, tc := range scanTable {
		t.Run(path.Base(tc.Name), tc.Run(ctx))
	}
}

var scanTable = []test.ScannerTestcase{
	{
		Domain: "docker.io",
		Name:   "tinkerpop/gremlin-console",
		Hash:   "sha256:e6e10dd7da4509f51dbdaf50f9d786f4ca0096ba14bfa7443f19d032e35f73f7",
		Want: []*claircore.Package{
			{
				Name:           "org.apache.tinkerpop:gremlin-groovy",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/gremlin-groovy/lib/gremlin-groovy-3.4.8.jar",
				RepositoryHint: "sha1:9ae4c997e7b38ef6f6bc72c53412434743705866",
			},
			{
				Name:           "org.apache.tinkerpop:gremlin-groovy",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/gremlin-groovy/plugin/gremlin-groovy-3.4.8.jar",
				RepositoryHint: "sha1:9ae4c997e7b38ef6f6bc72c53412434743705866",
			},
			{
				Name:           "org.apache.tinkerpop:tinkergraph-gremlin",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/tinkergraph-gremlin/lib/tinkergraph-gremlin-3.4.8.jar",
				RepositoryHint: "sha1:b438353c7514e468f983370a909328aa5957813a",
			},
			{
				Name:           "org.apache.tinkerpop:tinkergraph-gremlin",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/tinkergraph-gremlin/plugin/tinkergraph-gremlin-3.4.8.jar",
				RepositoryHint: "sha1:b438353c7514e468f983370a909328aa5957813a",
			},
			{
				Name:           "com.github.ben-manes.caffeine",
				Version:        "2.3.1",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/caffeine-2.3.1.jar",
				RepositoryHint: "sha1:d6aec5cbd26313a341ee7c034bd56d604f68bebe",
			},
			{
				Name:           "commons-codec:commons-codec",
				Version:        "1.14",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/commons-codec-1.14.jar",
				RepositoryHint: "sha1:3cb1181b2141a7e752f5bdc998b7ef1849f726cf",
			},
			{
				Name:           "commons-collections:commons-collections",
				Version:        "3.2.2",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/commons-collections-3.2.2.jar",
				RepositoryHint: "sha1:8ad72fe39fa8c91eaaf12aadb21e0c3661fe26d5",
			},
			{
				Name:           "commons-configuration:commons-configuration",
				Version:        "1.10",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/commons-configuration-1.10.jar",
				RepositoryHint: "sha1:2b36e4adfb66d966c5aef2d73deb6be716389dc9",
			},
			{
				Name:           "commons-lang:commons-lang",
				Version:        "2.6",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/commons-lang-2.6.jar",
				RepositoryHint: "sha1:0ce1edb914c94ebc388f086c6827e8bdeec71ac2",
			},
			{
				Name:           "org.apache.commons:commons-lang3",
				Version:        "3.8.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/commons-lang3-3.8.1.jar",
				RepositoryHint: "sha1:6505a72a097d9270f7a9e7bf42c4238283247755",
			},
			{
				Name:           "commons-logging:commons-logging",
				Version:        "1.2",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/commons-logging-1.2.jar",
				RepositoryHint: "sha1:4bfc12adfe4842bf07b657f0369c4cb522955686",
			},
			{
				Name:           "net.objecthunter:exp4j",
				Version:        "0.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/exp4j-0.4.8.jar",
				RepositoryHint: "sha1:cf1cfc0f958077d86ac7452c7e36d944689b2ec4",
			},
			{
				Name:           "org.apache.tinkerpop:gremlin-console",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-console-3.4.8.jar",
				RepositoryHint: "sha1:f001a2644ca44cf60fdde8dbd271e919168ec208",
			},
			{
				Name:           "org.apache.tinkerpop:gremlin-core",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-core-3.4.8.jar",
				RepositoryHint: "sha1:7d6074aa75fc8e219fd7456fa94312ba52922dac",
			},
			{
				Name:           "org.apache.tinkerpop:gremlin-driver",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-driver-3.4.8.jar",
				RepositoryHint: "sha1:53a55a34441c49ad7b933a7ddb4276d3e81dbe72",
			},
			{
				Name:           "com.esotericsoftware:kryo-shaded",
				Version:        "3.0.3",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "com.esotericsoftware:minlog",
				Version:        "1.3.0",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "com.esotericsoftware:reflectasm",
				Version:        "1.10.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "com.fasterxml.jackson.core:jackson-annotations",
				Version:        "2.9.10",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "com.fasterxml.jackson.core:jackson-core",
				Version:        "2.9.10",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "com.fasterxml.jackson.core:jackson-databind",
				Version:        "2.9.10.5",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "org.apache.tinkerpop:gremlin-shaded",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/gremlin-shaded-3.4.8.jar",
				RepositoryHint: "sha1:eecca88aa8b7e6ca0d85821a0b7df9f9b873e95b",
			},
			{
				Name:           "groovy",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-2.5.11-indy.jar",
				RepositoryHint: "sha1:1d90cbcff0947aaf43f31741b48839e5fe190f13",
			},
			{
				Name:           "groovy-cli-picocli",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-cli-picocli-2.5.11.jar",
				RepositoryHint: "sha1:d612d63d4ef1083bc05fcadc233b3d8f201d10f2",
			},
			{
				Name:           "groovy-console",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-console-2.5.11.jar",
				RepositoryHint: "sha1:3db61e9f5806dbf999bbeb44bf6c532540abc731",
			},
			{
				Name:           "groovy-groovysh",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-groovysh-2.5.11-indy.jar",
				RepositoryHint: "sha1:c4c372f662fdfb5f298aee7484553379ef207d1b",
			},
			{
				Name:           "groovy-json",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-json-2.5.11-indy.jar",
				RepositoryHint: "sha1:50233b0100cdb17a90a49a8aaaa9f0d020608600",
			},
			{
				Name:           "groovy-jsr223",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-jsr223-2.5.11-indy.jar",
				RepositoryHint: "sha1:c95ee910c2e74cfc37c73a6510b8476b146f3d10",
			},
			{
				Name:           "groovy-swing",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-swing-2.5.11.jar",
				RepositoryHint: "sha1:bcb2614685279e845f075cd1a22fe6950ce960b2",
			},
			{
				Name:           "groovy-templates",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-templates-2.5.11.jar",
				RepositoryHint: "sha1:941001acfda010320e2426a3b8fe056d6a1eb8f1",
			},
			{
				Name:           "groovy-xml",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/groovy-xml-2.5.11.jar",
				RepositoryHint: "sha1:3b1e713e805d7ea354a83d1c9e17a0754ea74132",
			},
			{
				Name:           "com.carrotsearch:hppc",
				Version:        "0.7.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/hppc-0.7.1.jar",
				RepositoryHint: "sha1:8b5057f74ea378c0150a1860874a3ebdcb713767",
			},
			{
				Name:           "org.apache.httpcomponents:httpclient",
				Version:        "4.5.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/httpclient-4.5.8.jar",
				RepositoryHint: "sha1:c27c9d6f15435dc2b6947112027b418b0eef32b9",
			},
			{
				Name:           "org.apache.httpcomponents:httpcore",
				Version:        "4.4.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/httpcore-4.4.11.jar",
				RepositoryHint: "sha1:de748cf874e4e193b42eceea9fe5574fabb9d4df",
			},
			{
				Name:           "org.apache.ivy",
				Version:        "2.3.0.final_20130110142753",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/ivy-2.3.0.jar",
				RepositoryHint: "sha1:c5ebf1c253ad4959a29f4acfe696ee48cdd9f473",
			},
			{
				Name:           "com.squareup:javapoet",
				Version:        "1.8.0",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/javapoet-1.8.0.jar",
				RepositoryHint: "sha1:e858dc62ef484048540d27d36f3ec2177a3fa9b1",
			},
			{
				Name:           "org.javatuples:javatuples",
				Version:        "1.2",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/javatuples-1.2.jar",
				RepositoryHint: "sha1:507312ac4b601204a72a83380badbca82683dd36",
			},
			{
				Name:           "org.mindrot:jbcrypt",
				Version:        "0.4",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/jbcrypt-0.4.jar",
				RepositoryHint: "sha1:af7e61017f73abb18ac4e036954f9f28c6366c07",
			},
			{
				Name:           "com.jcabi:jcabi-log",
				Version:        "0.14",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/jcabi-log-0.14.jar",
				RepositoryHint: "sha1:819a57348f2448f01d74f8a317dab61d6a90cac2",
			},
			{
				Name:           "com.jcabi:jcabi-manifests",
				Version:        "1.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/jcabi-manifests-1.1.jar",
				RepositoryHint: "sha1:e4f4488c0e3905c6fab287aca2569928fe1712df",
			},
			{
				Name:           "org.slf4j:jcl-over-slf4j",
				Version:        "1.7.25",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/jcl-over-slf4j-1.7.25.jar",
				RepositoryHint: "sha1:f8c32b13ff142a513eeb5b6330b1588dcb2c0461",
			},
			{
				Name:           "jline:jline",
				Version:        "2.14.6",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/jline-2.14.6.jar",
				RepositoryHint: "sha1:c3aeac59c022bdc497c8c48ed86fa50450e4896a",
			},
			{
				Name:           "log4j:log4j",
				Version:        "1.2.17",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/log4j-1.2.17.jar",
				RepositoryHint: "sha1:5af35056b4d257e4b64b9e8069c0746e8b08629f",
			},
			{
				Name:           "io.netty:netty-all",
				Version:        "4.1.49.Final",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/netty-all-4.1.49.Final.jar",
				RepositoryHint: "sha1:ffe903492be79f5bd8348b04c958de3734a22c6b",
			},
			{
				Name:           "picocli",
				Version:        "4.0.1",
				Kind:           "binary",
				PackageDB:      "jar:opt/gremlin-console/lib/picocli-4.0.1.jar",
				RepositoryHint: "sha1:282c164057d55e6b6af2de49e8930f3c760439da",
			},
			{
				Name:           "org.slf4j:slf4j-api",
				Version:        "1.7.25",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/slf4j-api-1.7.25.jar",
				RepositoryHint: "sha1:da76ca59f6a57ee3102f8f9bd9cee742973efa8a",
			},
			{
				Name:           "org.slf4j:slf4j-log4j12",
				Version:        "1.7.25",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/slf4j-log4j12-1.7.25.jar",
				RepositoryHint: "sha1:110cefe2df103412849d72ef7a67e4e91e4266b4",
			},
			{
				Name:           "org.yaml:snakeyaml",
				Version:        "1.15",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib/snakeyaml-1.15.jar",
				RepositoryHint: "sha1:3b132bea69e8ee099f416044970997bde80f4ea6",
			},
		},
		Scanner: &java.Scanner{},
	},
}
