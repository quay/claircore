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
			&claircore.Package{
				Name:           "org.apache.tinkerpop:gremlin-groovy",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/gremlin-groovy/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:gremlin-groovy",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/gremlin-groovy/plugin",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:tinkergraph-gremlin",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/tinkergraph-gremlin/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:tinkergraph-gremlin",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/ext/tinkergraph-gremlin/plugin",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.github.ben-manes.caffeine:caffeine",
				Version:        "2.3.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "commons-codec:commons-codec",
				Version:        "1.14",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "commons-collections:commons-collections",
				Version:        "3.2.2",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "commons-configuration:commons-configuration",
				Version:        "1.10",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "commons-lang:commons-lang",
				Version:        "2.6",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.commons:commons-lang3",
				Version:        "3.8.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "commons-logging:commons-logging",
				Version:        "1.2",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "net.objecthunter:exp4j",
				Version:        "0.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:gremlin-console",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:gremlin-core",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:gremlin-driver",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.tinkerpop:gremlin-shaded",
				Version:        "3.4.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.esotericsoftware:kryo-shaded",
				Version:        "3.0.3",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.esotericsoftware:reflectasm",
				Version:        "1.10.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.esotericsoftware:minlog",
				Version:        "1.3.0",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.fasterxml.jackson.core:jackson-databind",
				Version:        "2.9.10.5",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.fasterxml.jackson.core:jackson-annotations",
				Version:        "2.9.10",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.fasterxml.jackson.core:jackson-core",
				Version:        "2.9.10",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-cli-picocli",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-console",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-groovysh",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-json",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-jsr223",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-swing",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-templates",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.codehaus.groovy:groovy-xml",
				Version:        "2.5.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.carrotsearch:hppc",
				Version:        "0.7.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.httpcomponents:httpclient",
				Version:        "4.5.8",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.httpcomponents:httpcore",
				Version:        "4.4.11",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.apache.ivy:ivy",
				Version:        "2.3.0",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.squareup:javapoet",
				Version:        "1.8.0",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.javatuples:javatuples",
				Version:        "1.2",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.mindrot:jbcrypt",
				Version:        "0.4",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.jcabi:jcabi-log",
				Version:        "0.14",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "com.jcabi:jcabi-manifests",
				Version:        "1.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.slf4j:jcl-over-slf4j",
				Version:        "1.7.25",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "jline:jline",
				Version:        "2.14.6",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "log4j:log4j",
				Version:        "1.2.17",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "io.netty:netty-all",
				Version:        "4.1.49.Final",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "info.picocli:picocli",
				Version:        "4.0.1",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.slf4j:slf4j-api",
				Version:        "1.7.25",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.slf4j:slf4j-log4j12",
				Version:        "1.7.25",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
			&claircore.Package{
				Name:           "org.yaml:snakeyaml",
				Version:        "1.15",
				Kind:           "binary",
				PackageDB:      "maven:opt/gremlin-console/lib",
				RepositoryHint: "https://repo1.maven.apache.org/maven2",
			},
		},
		Scanner: &java.Scanner{},
	},
}
