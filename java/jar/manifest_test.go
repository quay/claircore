package jar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestParseManifest(t *testing.T) {
	t.Parallel()
	ctx := zlog.Test(context.Background(), t)

	md := os.DirFS("testdata/manifest")
	fs, err := fs.ReadDir(md, ".")
	if err != nil {
		t.Fatal(err)
	}
	// Tee the manifests for easier diagnosing.
	var buf bytes.Buffer
	for _, d := range fs {
		buf.Reset()
		f, err := md.Open(d.Name())
		if err != nil {
			t.Error(err)
			continue
		}
		tee := io.TeeReader(f, &buf)
		var i Info
		err = i.parseManifest(ctx, tee)
		f.Close()
		switch {
		case errors.Is(err, nil):
			t.Logf("%s: %+v", d.Name(), i)
		case errors.Is(err, errUnpopulated):
		default:
			t.Error(err)
		}
		t.Logf("%s: %+q", d.Name(), buf.String())
	}
}

func TestParseManifest_JenkinsPlugins(t *testing.T) {
	var i Info
	ctx := zlog.Test(context.Background(), t)
	for _, tc := range jenkinsPlugins {
		t.Run(tc.Name, func(t *testing.T) {
			err := i.parseManifest(ctx, strings.NewReader(tc.Contents))
			if err != nil {
				t.Fatal(err)
			}

			if !cmp.Equal(tc.ExpectedName, i.Name) {
				t.Error(cmp.Diff(tc.ExpectedName, i.Name))
			}
			if !cmp.Equal(tc.ExpectedVersion, i.Version) {
				t.Error(cmp.Diff(tc.ExpectedVersion, i.Version))
			}
		})
	}
}

type manifestTestCase struct {
	Name            string
	Contents        string
	ExpectedName    string
	ExpectedVersion string
}

var jenkinsPlugins = []manifestTestCase{
	{
		Name: "ghprb",
		Contents: `Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Created-By: Apache Maven
Built-By: ogondza
Build-Jdk: 1.8.0_275
Extension-Name: ghprb
Specification-Title: The Jenkins Plugins Parent POM Project
Implementation-Title: ghprb
Implementation-Version: 1.42.2
Group-Id: org.jenkins-ci.plugins
Short-Name: ghprb
Long-Name: GitHub Pull Request Builder
Url: https://wiki.jenkins-ci.org/display/JENKINS/GitHub+pull+request+b
 uilder+plugin
Plugin-Version: 1.42.2
Hudson-Version: 2.7
Jenkins-Version: 2.7
Plugin-Dependencies: build-flow-plugin:0.20;resolution:=optional,githu
 b:1.27.0,bouncycastle-api:2.16.1,credentials:2.1.14,git:3.3.1,github-
 api:1.92,job-dsl:1.63;resolution:=optional,matrix-project:1.11,plain-
 credentials:1.4,scm-api:2.1.0,script-security:1.25,structs:1.9,token-
 macro:2.1;resolution:=optional
Plugin-Developers: Sam Gleske:sag47:sam.mxracer@gmail.com
`,
		ExpectedName:    "org.jenkins-ci.plugins:ghprb",
		ExpectedVersion: "1.42.2",
	},
	{
		Name: "stackrox-container-image-scanner",
		Contents: `Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Created-By: Apache Maven
Built-By: runner
Build-Jdk: 1.8.0_362
Extension-Name: stackrox-container-image-scanner
Specification-Title: This plugin provides vulnerability scanning of co
 ntainer images for OS packages and language
         vulnerabilities using the StackRox Kubernetes Security Platform
Specification-Vendor: Red Hat
Implementation-Vendor: Red Hat
Implementation-Title: stackrox-container-image-scanner
Implementation-Version: 1.3.4
Group-Id: org.jenkins-ci.plugins
Short-Name: stackrox-container-image-scanner
Long-Name: StackRox Container Image Scanner
Url: https://github.com/stackrox/jenkins-plugin
Minimum-Java-Version: 1.7
Plugin-Version: 1.3.4
Hudson-Version: 2.164.1
Jenkins-Version: 2.164.1
Plugin-Developers: Red Hat:stackrox-k8s-security-platform:jenkins-plug
 in@stackrox.com
Plugin-License-Name: Apache 2 License
Plugin-License-Url: http://opensource.org/licenses/Apache-2.0
Plugin-ScmUrl: https://github.com/stackrox/jenkins-plugin
`,
		ExpectedName:    "org.jenkins-ci.plugins:stackrox-container-image-scanner",
		ExpectedVersion: "1.3.4",
	},
	{
		Name: "m2release",
		Contents: `Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Created-By: Apache Maven
Built-By: Kevin
Build-Jdk: 1.8.0_202
Extension-Name: m2release
Specification-Title: A plug-in that enables you to perform releases us
 ing the maven-release-plugin from Jenkins.
Implementation-Title: m2release
Implementation-Version: 0.16.3
Plugin-Class: org.jvnet.hudson.plugins.m2release.PluginImpl
Group-Id: org.jenkins-ci.plugins.m2release
Short-Name: m2release
Long-Name: Jenkins Maven Release Plug-in Plug-in
Url: http://wiki.jenkins-ci.org/display/JENKINS/M2+Release+Plugin
Compatible-Since-Version: 0.15
Minimum-Java-Version: 1.8
Plugin-Version: 0.16.3
Hudson-Version: 2.138.4
Jenkins-Version: 2.138.4
Plugin-Dependencies: maven-plugin:3.4,dashboard-view:2.0;resolution:=o
 ptional
Plugin-Developers: James Nord:teilo:,Christian Slama:m68k:,Dominik Bar
 tholdi:imod:
Plugin-License-Name: MIT License
Plugin-License-Url: http://www.opensource.org/licenses/mit-license.php
Plugin-ScmUrl: https://github.com/jenkinsci/m2release-plugin/
`,
		ExpectedName:    "org.jenkins-ci.plugins.m2release:m2release",
		ExpectedVersion: "0.16.3",
	},
	{
		Name: "ssh-credentials",
		Contents: `Manifest-Version: 1.0
Created-By: Maven Archiver 3.6.0
Build-Jdk-Spec: 11
Specification-Title: SSH Credentials Plugin
Specification-Version: 0.0
Implementation-Title: SSH Credentials Plugin
Implementation-Version: 305.v8f4381501156
Group-Id: org.jenkins-ci.plugins
Short-Name: ssh-credentials
Long-Name: SSH Credentials Plugin
Url: https://github.com/jenkinsci/ssh-credentials-plugin
Plugin-Version: 305.v8f4381501156
Hudson-Version: 2.346.1
Jenkins-Version: 2.346.1
Plugin-Dependencies: credentials:1139.veb_9579fca_33b_,trilead-api:1.67.
 vc3938a_35172f
Plugin-Developers: Stephen Connolly:stephenconnolly:,Oleg Nenashev:oleg_
 nenashev:,Matt Sicker:jvz:
Plugin-License-Name: MIT License
Plugin-License-Url: https://opensource.org/licenses/MIT
Plugin-ScmUrl: https://github.com/jenkinsci/ssh-credentials-plugin
`,
		ExpectedName:    "org.jenkins-ci.plugins:ssh-credentials",
		ExpectedVersion: "305.v8f4381501156",
	},
}
