<a name="unreleased"></a>
## [Unreleased]


<a name="v0.4.2"></a>
## [v0.4.2] - 2021-05-07
### Alpine
- [f92e1be](https://github.com/quay/claircore/commit/f92e1bea4f163be841fbc459c4b909a0512f1d04): implement driver.Configurable
### Aws
- [4738610](https://github.com/quay/claircore/commit/473861086b27d77e19aa6e788a60c1796d305ae1): add http.Client configurability
### Cicd
- [fe6cb92](https://github.com/quay/claircore/commit/fe6cb92b085e5907814dcb4f4ec756c2436baa3f): use golang major version tag for dev env
- [0a04053](https://github.com/quay/claircore/commit/0a04053358a6fa1a5d5a71fae0d4b29607a4457d): use quay.io/projectquay/golang image
- [d62b5ad](https://github.com/quay/claircore/commit/d62b5ad8ab8e4f83d8dda8173a6734c81e0df7ec): add golang-image workflow
### Crda
- [5146d8c](https://github.com/quay/claircore/commit/5146d8c775f21bac302369e91062bfafbf54eab0): implement driver.MatcherConfigurable
### Debian
- [3d2d700](https://github.com/quay/claircore/commit/3d2d7007b4726f0159c22f8867ae67225c153d9b): implement driver.Configurable
### Enrichments
- [9a3b349](https://github.com/quay/claircore/commit/9a3b349a3b7a23683e41ef55a3b242bc51edb43e): datamodel updates
### Fetcher
- [cd6b7fa](https://github.com/quay/claircore/commit/cd6b7fa9d78fd705965f56b2333a6fae72f633d7): remove DefaultClient usage
### Jsonblob
- [bd2487d](https://github.com/quay/claircore/commit/bd2487dabd7c1dd75868c3fce013a82cd1342cf3): fix copyops
### Libindex
- [eec427f](https://github.com/quay/claircore/commit/eec427fcf78e78d1f1654a997fb33385a7150fd5): use configurable http.Client
### Libvuln
- [34de61e](https://github.com/quay/claircore/commit/34de61ee0ef7ec47b7be2ddcd97928f92d61d9e6): add warn logs when not providing an http.Client
### Libvulnhttp
- [ef4ee5c](https://github.com/quay/claircore/commit/ef4ee5c29a12bf2c90cd84476942feed23448070): add HTTP client debugging flag
### Matchers
- [07fcc40](https://github.com/quay/claircore/commit/07fcc403a55296e6ce73dab45e3957839173d586): require http.Client
### Oracle
- [de18d67](https://github.com/quay/claircore/commit/de18d67e8d40773567c0549000790108c07c251a): add assertion for Configurable interface
### Ovalutil
- [d3106a3](https://github.com/quay/claircore/commit/d3106a3a2c3480f6621cc8bdd3b1cd6a5bc05340): implement driver.Configurable
### Photon
- [28341b9](https://github.com/quay/claircore/commit/28341b9d4b96f02baf1ca319812c7baec7bdfafa): add assertion for Configurable interface
### Pyupio
- [2cf6a9e](https://github.com/quay/claircore/commit/2cf6a9ef937a7cbe5dcb52fb88120aa8ba7c4049): implement driver.Configurable
### Registry
- [891a6df](https://github.com/quay/claircore/commit/891a6dfda0412160bf01dcd23fe6ccc056c284a8): require http.Client
### Rhel
- [5c873b4](https://github.com/quay/claircore/commit/5c873b422360f4a3107880b795c6d9b7e746ab19): add assertion for Configurable interface
- [2112153](https://github.com/quay/claircore/commit/2112153f33f8ec9e1ce3f3519cae7b972309db39): pass Client through Factory
- [ad16c39](https://github.com/quay/claircore/commit/ad16c397573c28f140285eee99925fe053554c75): make repo2cpe mapping a work stealing scheme
### Suse
- [0039063](https://github.com/quay/claircore/commit/00390632187fdbd04cb914a24056501cee7b3827): add assertion for Configurable interface
### Ubuntu
- [2976e93](https://github.com/quay/claircore/commit/2976e93452bb3afcaad9593f666fad021995e644): implement driver.Configurable
### Updater
- [9145453](https://github.com/quay/claircore/commit/914545363ea38e6dda086463bf7a657f14b1458b): report error on nil *http.Client
- [ece3005](https://github.com/quay/claircore/commit/ece3005d6dbaef946a9ca3dab3b8662e0b2013c5): call Configure method if present
### Updates
- [59bec1f](https://github.com/quay/claircore/commit/59bec1fb35f589485c5e5775199efa2d5b4bd035): call Configure method if present
- [de4be78](https://github.com/quay/claircore/commit/de4be78fc0e8104fb64af50cd18851dc383780a8): drop updater when configuration fails
- [9bc81ca](https://github.com/quay/claircore/commit/9bc81ca1303274f280a0fb8348cffb079674a0ae): consolidate update logic
- [9ade4e1](https://github.com/quay/claircore/commit/9ade4e1808bc518a8997f1c01980d1c9a599c857): add LockSource interface
### Vulnstore
- [e9cd964](https://github.com/quay/claircore/commit/e9cd964a7ae5ce923e86ae110c57222c02de2589): fix getting update operation diff
- [bfafd2f](https://github.com/quay/claircore/commit/bfafd2f7ad2b4d4b33fb0ab644bb09191d42732c): enrichment migration

<a name="v0.4.1"></a>
## [v0.4.1] - 2021-05-04
### All
- [def957b](https://github.com/quay/claircore/commit/def957b472e57fc18eb127f840b4802da4eb6d52): return empty byte slices from MarshalText
### Chore
- [990cd41](https://github.com/quay/claircore/commit/990cd41b7f73730d2360a1ecd35c00613f77d789): v0.4.1 changelog bump
### Cicd
- [b764338](https://github.com/quay/claircore/commit/b76433852ca2c1760a202b9fd383a9f24ab51327): remove chglog fork
### Crda
- [1405b57](https://github.com/quay/claircore/commit/1405b573a27c08e12d974f0f2b7f4dcf1b149183): use bulk API in remotematcher
### Indexer
- [905d6f3](https://github.com/quay/claircore/commit/905d6f3dae321e0a445964abd2d0e06f0376cf25): Implement package indexer for maven
 - Fixes [#236](https://github.com/quay/claircore/issues/236)### Introspection
- [9ecfbb0](https://github.com/quay/claircore/commit/9ecfbb0413648f1183dfedb27dc13b02b115d564): Fix a typo in the query label for the distributionbylayer metric
### Libindex
- [5877dc1](https://github.com/quay/claircore/commit/5877dc1a192514204f33a22bf82ac425fd3df464): set concurrency number
- [254c094](https://github.com/quay/claircore/commit/254c0945b0af17cd9c3b97815d3505b5b8286d3d): AffectedManifests to be bounded
### Matcher
- [78f069b](https://github.com/quay/claircore/commit/78f069b30625424146cb9294edcdc153646abd39): add ability to return multiple matchers from same type
### Testing
- [bb26dab](https://github.com/quay/claircore/commit/bb26dabc4e4118d5d8b1e43aef6ecbe0e74e70e6): add unittest
- [d6d7e8e](https://github.com/quay/claircore/commit/d6d7e8e352c0f86220f6acf85571b82d67a6cc37): maxConns to 10

<a name="v0.4.0"></a>
## [v0.4.0] - 2021-04-05
### Chore
- [f56014b](https://github.com/quay/claircore/commit/f56014b44205f4390fc9352e63b2545a28bcebfb): v0.4.0 changelog bump
### Cicd
- [ab1208b](https://github.com/quay/claircore/commit/ab1208b03c8f85de35f528eefdc200a8e7f41b7a): update doc building to main
### Docs
- [99d6eff](https://github.com/quay/claircore/commit/99d6eff84baa2f0229f53830cd981fd93682c090): note default updater URLs
### Introspection
- [880166b](https://github.com/quay/claircore/commit/880166b1f81200c6044b5db4011f2c783d5eaeb1): datastore metrics
### Python
- [24aad97](https://github.com/quay/claircore/commit/24aad97311e9ceb14b6d0d9718a35a4a58a3b97d): force re-fetch/parse
- [1f881b5](https://github.com/quay/claircore/commit/1f881b5c578385ad522e0bb49bfbe6510e262f57): update package scanner version
### Rhel
- [8cc2823](https://github.com/quay/claircore/commit/8cc282379a39c822b125a7c424b753b4fe9586eb): discard unaffected vulnerabilities
- [ddd2621](https://github.com/quay/claircore/commit/ddd2621e8c3eb91b91b4b912b1b93bbbc2c7d785): treat vulns without FixedInVersion as unfixed

<a name="v0.3.3"></a>
## [v0.3.3] - 2021-03-18
### Chore
- [278fd77](https://github.com/quay/claircore/commit/278fd77be94ebaea46819da7a1d7bf8a054f898d): v0.3.3 changelog bump
### Cicd
- [6e26297](https://github.com/quay/claircore/commit/6e26297141d97342b0dc68b20f1494e364f7e036): fix release failure

<a name="v0.3.2"></a>
## [v0.3.2] - 2021-03-18
### Chore
- [280bf2b](https://github.com/quay/claircore/commit/280bf2b93a452642d9ae41ee59afbbb71a4790b8): v0.3.2 changelog bump
- [bfb37f0](https://github.com/quay/claircore/commit/bfb37f01c616db804aab3f6a361404a69a79ce28): update comments in distribution scanners
### Chore: Release Quay.Io/Claircore/Golang
- [d3ac00e](https://github.com/quay/claircore/commit/d3ac00e1808c61f47a8505de4931b694c54e5b7a): 1.16
### Cicd
- [7d55319](https://github.com/quay/claircore/commit/7d55319f6202145cbfe38faf3fde183642c53123): sort changelog by semver
- [eae2b15](https://github.com/quay/claircore/commit/eae2b158422d7f53bce9a43a3a6e83f106ef2092): bump out go1.14 and bump in go1.16
- [d9f28c4](https://github.com/quay/claircore/commit/d9f28c4f839c4c95cd4b9b6ed3f4d1226c7bcea3): gh action echo branch
- [6efb496](https://github.com/quay/claircore/commit/6efb496f0e8ddf9dc71857ab8ffd5b8753314a59): fix gh action script
- [67fa955](https://github.com/quay/claircore/commit/67fa9554f929364f7c6d9fad47011d627efe5578): filter tags for stable branch releases
### Fetcher
- [a30c62d](https://github.com/quay/claircore/commit/a30c62d09f709577f550e6be195c79dc6034e62f): relax allowable gzip types
 - Closes [#303](https://github.com/quay/claircore/issues/303)### Fix
- [892ba0c](https://github.com/quay/claircore/commit/892ba0c1d25ee2f3975e2fd1a1f3de569b149f5c): comments and docs
- [7b054c2](https://github.com/quay/claircore/commit/7b054c2ed9226ee428019db3816d1e1c8a7f6f90): provide a way for default and out-of-tree matchers
### Indexer
- [47b877a](https://github.com/quay/claircore/commit/47b877a291acb619f2fa7a7acc34e17e7f3af3af): regen indexer test data
### Libindex
- [f49cea5](https://github.com/quay/claircore/commit/f49cea5d9de7eecdc7a260c274d39957788aff3c): remove annoying log
### Matcherfactory
- [25dd763](https://github.com/quay/claircore/commit/25dd763a32d25df98036039ba8871c99bf8ea21b): fix typos in comments
### Matchers
- [14bc1d2](https://github.com/quay/claircore/commit/14bc1d2e61b383c9e945efc170188dbe5493bdb7): add factory pattern
### Python
- [2cef538](https://github.com/quay/claircore/commit/2cef538f9b607447c3d9d186576cae5b0e115f63): move to traditional mapping
### Rhel
- [5eba440](https://github.com/quay/claircore/commit/5eba4405925a56e073b10cf4959f9fca0788a666): fix cpe mapping type assertion
### Vulnstore
- [aa46c6b](https://github.com/quay/claircore/commit/aa46c6bd1535df5850c52c3b219c0f48c6822abd): update-diff optimize
- [7856456](https://github.com/quay/claircore/commit/78564563897a3f1573987ae05fb6ecb6539abe57): chunked vuln cleanup

<a name="v0.3.1"></a>
## [v0.3.1] - 2021-02-11
### Chore
- [e5743e3](https://github.com/quay/claircore/commit/e5743e3fd13268bda568de194d9f04d32c12b9f3): v0.3.1 changelog bump
### Libindex
- [2cf7d4a](https://github.com/quay/claircore/commit/2cf7d4ad5002677f3f8e0baf047d66acbe93ea47): limit MaxConns in controller pool to 1

<a name="v0.3.0"></a>
## [v0.3.0] - 2021-02-05
### Chore
- [533316c](https://github.com/quay/claircore/commit/533316c18965c9007f1fb60bead2f33cf012d715): v0.3.0 changelog bump
### Cicd
- [1d47ccd](https://github.com/quay/claircore/commit/1d47ccd24fe3ececf141779ce535472b2da9a0e8): fix release notes
### Docs
- [480dcf7](https://github.com/quay/claircore/commit/480dcf740ae45f89f6adb22465e3d77f517871f0): various doc fixups
### Libvuln
- [b0ba2f2](https://github.com/quay/claircore/commit/b0ba2f2a0929c17cd349a733392eb6180558865b): rework constuctor
### Remotematcher
- [b95d984](https://github.com/quay/claircore/commit/b95d9840113db0b3ca4937a10f3a8eef920d2ffd): Implement RemoteMatcher for CRDA
### Severity-Mapping
- [fc1aa30](https://github.com/quay/claircore/commit/fc1aa30841820e309653733db660c56deae033f8): remove defcon1 severity
### Updates
- [966de96](https://github.com/quay/claircore/commit/966de967953448b7358fbbfc26e7905ad64b71a2): perform implicit run
### Vulnstore
- [20a4437](https://github.com/quay/claircore/commit/20a4437a078309864db9a0fad8a0f4c81b6059a4): fix gc live lock
- [1f4717f](https://github.com/quay/claircore/commit/1f4717f22ad65342fb127f718bd7a55faed23cd1): add Initialized method

<a name="v0.2.0"></a>
## [v0.2.0] - 2021-01-19
### All
- [3a4e3d3](https://github.com/quay/claircore/commit/3a4e3d3e053cd3856795565e1b674e2ba4b03900): logging switch
### Alpine
- [f639452](https://github.com/quay/claircore/commit/f639452bfe3872d730e11462e117f122a5fcde7a): fix typo of ecosystem
### Aws
- [1cdf08c](https://github.com/quay/claircore/commit/1cdf08cc721306466222555c552f41994c08da49): test cleanup
### Cctool
- [826aacb](https://github.com/quay/claircore/commit/826aacbf6ed9abcd78529fedc91417a511743863): copy loop variable
### Chore
- [4fac8b5](https://github.com/quay/claircore/commit/4fac8b5e210d2446d13680c2f3d062c0efb02efa): v0.2.0 changelog bump
### Cicd
- [e749f3b](https://github.com/quay/claircore/commit/e749f3b414416f823a545753419c9574cecaecc7): drop go1.13 support
- [733d8f1](https://github.com/quay/claircore/commit/733d8f1560b6c3d48560f7cc170536578fa7b7ac): use quay.io/claircore/golang in CI
### Claircore
- [316fc25](https://github.com/quay/claircore/commit/316fc25dfc829bd57d3716ff9dce54af5a19c899): lint test names
### Controller
- [e36877c](https://github.com/quay/claircore/commit/e36877c2d7f6a7cdf627b69472c72cf4496146d2): test cleanup
### Debian
- [31956a9](https://github.com/quay/claircore/commit/31956a91be90cb37bd00d23e19b7a3584ecc9cd0): test cleanup
### Fastesturl
- [cd55757](https://github.com/quay/claircore/commit/cd557578d12a62345e1a7d34304e3bd678a3db3c): use Cleanup method in tests
### Fetch
- [5ac709b](https://github.com/quay/claircore/commit/5ac709b5fb90641ee0a0972faf9a826cba278063): turn layer fetcher into a generic fetcher
### Go.Mod
- [eed4aaa](https://github.com/quay/claircore/commit/eed4aaa16ee12899d728b0f6f35cba4a5f9aca25): remove testify dependency
### Go.Sum
- [11df716](https://github.com/quay/claircore/commit/11df71637e1291477846c199d6352dcf7f66fbb5): clean sum database
### Indexer
- [313c8c4](https://github.com/quay/claircore/commit/313c8c43e180b080c675b4e0629485c76f553cbd): filter scanners during manifest check
### Layerscanner
- [4695c34](https://github.com/quay/claircore/commit/4695c348ad4bb6c3d7038dd4f2f612e449fdd357): test cleanup
- [0615a7b](https://github.com/quay/claircore/commit/0615a7b0550e5326e06c69354cd0d00647b7abb6): return unused error
### Libindex
- [ddb6b59](https://github.com/quay/claircore/commit/ddb6b5951bf9e053b4e3dad686dc2792b9b33877): remove sqlx
- [bf73eb8](https://github.com/quay/claircore/commit/bf73eb8663872ad42efe84852a0c1cc3bda07c44): return pointer to AffectedManifests
### Libvulnhttp
- [f31eec7](https://github.com/quay/claircore/commit/f31eec798c64c1ecd81b54906d3b49ab28231ed1): add DisableBackgroundUpdates config option
### Linux
- [8bb87e2](https://github.com/quay/claircore/commit/8bb87e23e68ec95b4f110cafdb9f473798113851): lint test name
### Misc
- [4840e07](https://github.com/quay/claircore/commit/4840e07d7f9b423084d450843d1f1b11048e1190): go vet fixes
### Photon
- [e6e2310](https://github.com/quay/claircore/commit/e6e2310b90ff2bdff09e2f84575cc49764a26e4e): add normalized severity
### Postgres
- [a1519ae](https://github.com/quay/claircore/commit/a1519ae885e2a9cfcee60e7dd4f28a18bab69a80): test cleanup
- [f865df5](https://github.com/quay/claircore/commit/f865df54ed9152bc992956ac71822d4d2466a35c): lint test name
- [bb8324d](https://github.com/quay/claircore/commit/bb8324d9aff155f87b52c4060abe985d48d0dcee): check subtest return instead of closure
- [46d391e](https://github.com/quay/claircore/commit/46d391eb1e4eca7999d7a4149291d52c4bd228ec): use Cleanup in tests
- [b3d19dd](https://github.com/quay/claircore/commit/b3d19ddadbb520f13371b69434ead88006e68755): use Cleanup in tests
- [8017e85](https://github.com/quay/claircore/commit/8017e8535c5c8f61f8fa6f92d25de1531ab72825): remove distlock sqlx implementation
- [e19e115](https://github.com/quay/claircore/commit/e19e115e80c9040be0e2142eea37c4165f0eba22): remove test harness sqlx usage
- [d84781f](https://github.com/quay/claircore/commit/d84781f7800ffeb352303031e47776df7e56b411): remove indexer sqlx usage
- [947e853](https://github.com/quay/claircore/commit/947e85375c6f53d23521fa0294cf0ea8fa575835): remove unused file
- [0cc6579](https://github.com/quay/claircore/commit/0cc6579839ec54e03e1456ac4a2444c269010795): fix update_operation response
### Rhel
- [b7a279c](https://github.com/quay/claircore/commit/b7a279ceecd47a87460be86b0dc93b2987a17414): lint test names
### Updaters
- [886d62b](https://github.com/quay/claircore/commit/886d62bdbee04ab01ce0237d69145907b33ee893): fix WithEnabled option
- [5385f5d](https://github.com/quay/claircore/commit/5385f5d5b78486e6f73f00e70d2cd21d57a17827): consolidate into manager
### Vulnstore
- [77df2c7](https://github.com/quay/claircore/commit/77df2c77881678726d601df50f0e2600de3cb67f): implement active gc

<a name="v0.1.25"></a>
## [v0.1.25] - 2021-04-16
### Chore
- [6f7bc34](https://github.com/quay/claircore/commit/6f7bc341c2dbaa92300b07fe6eec8ae753b75fcf): v0.1.25 changelog bump
### Cicd
- [9ba3cdc](https://github.com/quay/claircore/commit/9ba3cdc40bab372b35a4766e70ea176a37501b79): use git-chglog fork to sort by semver
- [aaab793](https://github.com/quay/claircore/commit/aaab793089a1785b63061f6fba0a877cb0d38a10): sort changelog by semver
### Indexer
- [ed50b6a](https://github.com/quay/claircore/commit/ed50b6a8f39fba597c48c967c0985721a9ed2bea): filter scanners during manifest check

<a name="v0.1.24"></a>
## [v0.1.24] - 2021-03-25
### Chore
- [8060abe](https://github.com/quay/claircore/commit/8060abe904a11c3b84aac45117b81fc3e1e8f362): v0.1.24 changelog bump
### Libvuln
- [0823927](https://github.com/quay/claircore/commit/082392732df1a6bfdaa49b6d17f7cb7f074fe7f6): sync migrations with upstream
### Python
- [da6e417](https://github.com/quay/claircore/commit/da6e417ed0451d09b08a1ee3933552a265813091): force re-fetch/parse
- [e5e767b](https://github.com/quay/claircore/commit/e5e767b2d4605bbcdccd38ca714e6309bc99ef48): update package scanner version
 -  [#348](https://github.com/quay/claircore/issues/348)
<a name="v0.1.23"></a>
## [v0.1.23] - 2021-03-11
### Chore
- [8ec6001](https://github.com/quay/claircore/commit/8ec600102759ce8ee55935d02cd46f24f091e81e): v0.1.23 changelog bump
### Cicd
- [62575fd](https://github.com/quay/claircore/commit/62575fdb7181d456a3507887bee6c06379fe50e5): bump out go1.14 and bump in go1.16
### Fetcher
- [fef216a](https://github.com/quay/claircore/commit/fef216a02f17792913850ccbc82d94abcf90bb64): relax allowable gzip types
 - Closes [#303](https://github.com/quay/claircore/issues/303)### Indexer
- [6bf358b](https://github.com/quay/claircore/commit/6bf358b384114bf440db8c2f70be5eee8b6d71cd): regen indexer test data
### Python
- [763ccdc](https://github.com/quay/claircore/commit/763ccdc115b3d05dcf8572d0f1374303f81b674c): move to traditional mapping

<a name="v0.1.22"></a>
## [v0.1.22] - 2021-02-12
### Chore
- [a9c9919](https://github.com/quay/claircore/commit/a9c99190124272360804571c0540d1b0a6b9edbd): v0.1.22 changelog bump
### Cicd
- [d493b6f](https://github.com/quay/claircore/commit/d493b6f685344ce8de0bafc410e757d95f77b007): fix release notes

<a name="v0.1.21"></a>
## [v0.1.21] - 2021-02-12
### Chore
- [bf12f91](https://github.com/quay/claircore/commit/bf12f910ba89a92beb0ef2c01bf0a676c2c7ed06): v0.1.21 changelog bump
### Rhel
- [17a73b5](https://github.com/quay/claircore/commit/17a73b58e3092bca946582c68367fc9ccad0183d): fix cpe mapping type assertion
### Reverts
- cicd: use CI golang image from quay.io


<a name="v0.1.20"></a>
## [v0.1.20] - 2020-12-11
### Alpine
- [98d3828](https://github.com/quay/claircore/commit/98d3828bb616ec5e3096575670e3f1a8f7430ee8): switch to JSON security DB
### Chore
- [2313419](https://github.com/quay/claircore/commit/231341985ebe018d1970b70d3c9ebd55a2d1a6cd): v0.1.20 changelog bump
### Cicd
- [97fa28b](https://github.com/quay/claircore/commit/97fa28bcb92a7b0db1b15cfb6cc45bd678d3f268): use CI golang image from quay.io
### Docs
- [00d4fcc](https://github.com/quay/claircore/commit/00d4fcc075535b582bff5ce9d0b7ba62c1226373): fix couple typos in libvuln_usage.md
### Rhel
- [baff663](https://github.com/quay/claircore/commit/baff66333b025d863779cea58e1a5aedd22a4bb3): ignore rhel-7-alt OVAL stream

<a name="v0.1.19"></a>
## [v0.1.19] - 2020-12-03
### Chore
- [cfa74e1](https://github.com/quay/claircore/commit/cfa74e1dc0d95c3bfcf12bafe77c502cc8db7c09): v0.1.19 changelog bump
### Docs
- [e2eeae0](https://github.com/quay/claircore/commit/e2eeae0dd5d6b4031b79cbb74c933677c7dd405d): indexer data model
### Dpkg
- [8025828](https://github.com/quay/claircore/commit/8025828d8e318c2f3a785b9ff9ee4f5c1c848735): add checks to discovered paths
### Indexer
- [f493a89](https://github.com/quay/claircore/commit/f493a890e51ed0afa3d77e8615a546c43603ab83): utilize migration for data model refactor
- [65aced8](https://github.com/quay/claircore/commit/65aced8a69f01806a5f4e2b1773ac131f7e7e828): e2e with multiple scanners
- [f31ca4c](https://github.com/quay/claircore/commit/f31ca4cd1f75e0de3d8e13617ffe704cbcb24aa8): database refactor

<a name="v0.1.18"></a>
## [v0.1.18] - 2020-12-02
### Chore
- [2dc2e58](https://github.com/quay/claircore/commit/2dc2e5853916b12089da5be219595335b6c2a350): v0.1.18 changelog bump
### Cicd
- [e80d4c7](https://github.com/quay/claircore/commit/e80d4c74e6461b7fd53fa02de0a6d945264a5a1e): bump create pull request action
### Oval
- [b6f61ac](https://github.com/quay/claircore/commit/b6f61acb71b85143b7c0ba19dffb39d2cfbbe890): rpm and dpkg parser updates

<a name="v0.1.17"></a>
## [v0.1.17] - 2020-11-30
### Chore
- [6ffe592](https://github.com/quay/claircore/commit/6ffe592a864fe92e44b65d63d3576f4be2c5ab58): v0.1.17 changelog bump
### Cicd
- [efbc55b](https://github.com/quay/claircore/commit/efbc55b8d5b27bdc32aeb6fdb60ebd3a569037a4): github actions set-env fix

<a name="v0.1.16"></a>
## [v0.1.16] - 2020-11-25
### Chore
- [c07b9dc](https://github.com/quay/claircore/commit/c07b9dc160eaad0688238998f8c5981389f57c8f): v0.1.16 changelog bump
### Documentation
- [268b037](https://github.com/quay/claircore/commit/268b037b0c8dd3180844739b2bc229d88412674a): indexer state diagram update
### Ovaldebug
- [6986794](https://github.com/quay/claircore/commit/69867941a721f6e2b8535085bc72107ced956a8b): add tool for testing parsing of OVAL
### Ovalutil
- [aa1927a](https://github.com/quay/claircore/commit/aa1927a8b0edb99317740c53893abc1ecbe0720e): fix dpkg "name caching" bug
- [f9dea3a](https://github.com/quay/claircore/commit/f9dea3aea8a72ea2107315e53b1e29488cc64f40): update vulnerability heuristic
### Ubuntu
- [6d61f87](https://github.com/quay/claircore/commit/6d61f871cf27dbed97e07f3c43f0d77ee7c7a837): attempt to add normalized severity
### Updater
- [378deef](https://github.com/quay/claircore/commit/378deef66294dfdbfacbb08ef1198ac6328b28dd): remove updater diff limit ([#265](https://github.com/quay/claircore/issues/265))
 -  [#265](https://github.com/quay/claircore/issues/265)
<a name="v0.1.15"></a>
## [v0.1.15] - 2020-11-02
### Alpine
- [16f63d4](https://github.com/quay/claircore/commit/16f63d40f177ac71b71c164dab0ce79589df5c7c): use new versions, upstream databases
- [e1f3e1f](https://github.com/quay/claircore/commit/e1f3e1f29405dfe89c4af5de98e7dc1c386c7efc): add new versions
- [c4367d5](https://github.com/quay/claircore/commit/c4367d5e7b8ef9392920e321984299cbeb51bd1d): fix yaml tag
### Chore
- [266a577](https://github.com/quay/claircore/commit/266a577d94b2376d3d16f2818c8c2ce144ccd021): v0.1.15 changelog bump
### Etc
- [94aa5f0](https://github.com/quay/claircore/commit/94aa5f0e8acc81d4b20e9064c7b0fae22043190c): update podman yaml
### Matcher
- [9b9c113](https://github.com/quay/claircore/commit/9b9c1135c8418759c3fd30686fcf6a5ee423bb42): add apk specific version parser for alpine
 -  [#254](https://github.com/quay/claircore/issues/254)
<a name="v0.1.14"></a>
## [v0.1.14] - 2020-10-26
### Rpm
- [04cb53c](https://github.com/quay/claircore/commit/04cb53cd0090dc60cf240ac4dd46db297ee8b18f): fix error handling in WalkFunc

<a name="v0.1.13"></a>
## [v0.1.13] - 2020-10-19
### Chore
- [b194f51](https://github.com/quay/claircore/commit/b194f51623795537a24ebd427346ed97db88c724): v0.1.13 changelog bump
### Pyupio
- [6569e25](https://github.com/quay/claircore/commit/6569e25ab26d551c4a2f4c8ddc2e3f57e6a4f9cf): handle database schema change

<a name="v0.1.12"></a>
## [v0.1.12] - 2020-10-19
### Chore
- [fc45b99](https://github.com/quay/claircore/commit/fc45b99bae52292efe0cdd8416934eb237109d5e): v0.1.12 changelog bump
### Updaters
- [1fd140d](https://github.com/quay/claircore/commit/1fd140de619ae3c026f2504d4ad0b017142910f4): do not kill loop on error

<a name="v0.1.11"></a>
## [v0.1.11] - 2020-10-08
### Chore
- [a8dd1cd](https://github.com/quay/claircore/commit/a8dd1cdcbbcda141ba4b451360fc9ce99229ce8c): v0.1.11 changelog bump
### Cicd
- [9b7d461](https://github.com/quay/claircore/commit/9b7d46143fd75e630c800254a116a4894aabc81b): copy some changes from clair's CI workflows
### Oval
- [f33a45d](https://github.com/quay/claircore/commit/f33a45df91d63c10877d1e6fde922166ad25b8e9): check lookup type ([#244](https://github.com/quay/claircore/issues/244))
 -  [#244](https://github.com/quay/claircore/issues/244)### Repo2cpe
- [eec2473](https://github.com/quay/claircore/commit/eec247383c5fe5c05cc9947a4f603b26b03de32e): add errorchecking

<a name="v0.1.10"></a>
## [v0.1.10] - 2020-10-01
### Affected Manifests
- [f8f0ff2](https://github.com/quay/claircore/commit/f8f0ff249f69fa812a58dc7c759ebcc04ae2a483): Use mather's Filter() in omnimatcher
- [aebd3a8](https://github.com/quay/claircore/commit/aebd3a8f5d4479409b283ffb22f8aaad63172e61): Add missing properties into affected manifest query
### Chore
- [9ba63f8](https://github.com/quay/claircore/commit/9ba63f8df6aab352e841ed819da53c371e4b0bcc): v0.1.10 changelog bump
### Cicd
- [d118d98](https://github.com/quay/claircore/commit/d118d987a5a8c3219d2dc1f87411197d99386c04): force no flags for regexp commit check
### Postgres
- [2df1697](https://github.com/quay/claircore/commit/2df1697d6126155e731055d164badeb783fc17b0): remove warning in common case
### Updater
- [c6b1bc9](https://github.com/quay/claircore/commit/c6b1bc9c5fd6deef5541979e3af1c5cf3c2e3961): use pointer receiver for errmap methods

<a name="v0.1.9"></a>
## [v0.1.9] - 2020-09-28
### Chore
- [1ecb4be](https://github.com/quay/claircore/commit/1ecb4be8dbcc67c902d3373981d33c3122b1baab): v0.1.9 changelog bump
### Layerscanner
- [4a1b872](https://github.com/quay/claircore/commit/4a1b872eeb07b6a66675bfa5bb603eb3d563f8b9): prevent misleading log line
### Vulnstore
- [6295f37](https://github.com/quay/claircore/commit/6295f370f5aaca200966187585424da8db4983cf): limit diffs

<a name="v0.1.8"></a>
## [v0.1.8] - 2020-09-23
### Chore
- [ce4f428](https://github.com/quay/claircore/commit/ce4f428faa690ed137acf5fadf33b8bafb5c4d65): v0.1.8 changelog bump
### Cicd
- [1566fc5](https://github.com/quay/claircore/commit/1566fc58d4d2659514240c382a1c6f7dc38da194): fix commit check regexp
### Makefile
- [1d9b607](https://github.com/quay/claircore/commit/1d9b6071a0bb802314926cf8a0bf482e4421055c): handle SELinux permissions for volume in docker-compose
### Rpm
- [d75ba4c](https://github.com/quay/claircore/commit/d75ba4c0e7dedb30146d31f567cd42e25b6dee0b): wait til command is finished
- [3008cba](https://github.com/quay/claircore/commit/3008cbadfcaf7dae4c00400c7e98f76d3e6b9998): Reduce database file to Packages

<a name="v0.1.7"></a>
## [v0.1.7] - 2020-09-15
### Chore
- [123b812](https://github.com/quay/claircore/commit/123b812b02b26de9146dcf5fed3c620864ecf2be): v0.1.7 changelog bump
### RHEL
- [f4d10b5](https://github.com/quay/claircore/commit/f4d10b53bcb1361f5de446c42ae0f4d271f070c3): Use last-modified to cache data

<a name="v0.1.6"></a>
## [v0.1.6] - 2020-09-11
### Chore
- [8c8cb3b](https://github.com/quay/claircore/commit/8c8cb3b6d51aa0a2cc4bcce2a7cc4d87a478a4f5): v0.1.6 changelog bump
### Cicd
- [ff6af2a](https://github.com/quay/claircore/commit/ff6af2ad163bb09b4d30fd5c37548c6bb6999db3): new release and change log process
- [40c7a28](https://github.com/quay/claircore/commit/40c7a28229e14245e814ef66bdcfa814ad22b4b1): new release and change log process
### Postgres
- [ff884b7](https://github.com/quay/claircore/commit/ff884b76b2befcc89ba3c7c5f1babeaeadf66293): manage the number of update_operations

<a name="v0.1.5"></a>
## [v0.1.5] - 2020-09-11
### Testing
- [40861cf](https://github.com/quay/claircore/commit/40861cfc63a7c53d4d009b15d9726d90a246d70a): bump golang 1.15 local dev

<a name="v0.1.4"></a>
## [v0.1.4] - 2020-09-10
### Goval
- [6f3dbd5](https://github.com/quay/claircore/commit/6f3dbd523ce473249e4e84800e48f6264f9c80b1): bump goval for ubuntu date fix

<a name="v0.1.3"></a>
## [v0.1.3] - 2020-09-03
### Coalescer
- [ee37a8f](https://github.com/quay/claircore/commit/ee37a8f780591d870b352a70bcd0955b04ed1a10): refactor of the linux coalescer
### Docs
- [4b3bc5b](https://github.com/quay/claircore/commit/4b3bc5b31b7eaf5a48b507685f93491bfc478dbc): prose pr fixes
- [b92a4cc](https://github.com/quay/claircore/commit/b92a4cc7fcd50d397d29ce2a6ae8e68cb812f4e1): rework md book

<a name="v0.1.2"></a>
## [v0.1.2] - 2020-09-02
### Rhel
- [9e3dfee](https://github.com/quay/claircore/commit/9e3dfee2a4115ff5393697a713689ee5aa811979): fix config struct tag

<a name="v0.1.1"></a>
## [v0.1.1] - 2020-08-26
### Cctool
- [2bb0b31](https://github.com/quay/claircore/commit/2bb0b31e3b519d9f453a83449b68b783bb885b41): use updater defaults
### Libvuln
- [823ffdc](https://github.com/quay/claircore/commit/823ffdc895f8f550cae544e554bd047f04d4e511): use updater defaults
- [c89c59a](https://github.com/quay/claircore/commit/c89c59a1bdbaf70760ddfdd05c185c71f18615dd): re-add matchers that got lost somehow
- [104c5f3](https://github.com/quay/claircore/commit/104c5f3290d04bb361eb65ef172a47b8183d02bd): add OfflineImport function
### Libvulnhttp
- [fc85f57](https://github.com/quay/claircore/commit/fc85f573d537dd4be2af17b75c90bad945382fe8): call new defaults register function
### Updater
- [006f540](https://github.com/quay/claircore/commit/006f5408c70a846176bba84005975a7042c93306): set up an updater registry and defaults

<a name="v0.1.0"></a>
## [v0.1.0] - 2020-08-11
### Add
- [f31f160](https://github.com/quay/claircore/commit/f31f160b430a3a5572e901c0ddd143b78627ccfe): Oval operation/arch matcher
### Alpine
- [736017c](https://github.com/quay/claircore/commit/736017c7fbb48d4c329741b800af9f407388730c): use etag instead of date
### Arch Op
- [6b9c72f](https://github.com/quay/claircore/commit/6b9c72f979ac30b10284b8f90549494cbc76ab34): turn into string, implement pattern match
### Aws
- [1b6b49a](https://github.com/quay/claircore/commit/1b6b49a8cc298645f01b51855e2b48fb945966c5): use manifest checksum
### Cctool
- [cd8b332](https://github.com/quay/claircore/commit/cd8b3325848c0991bd4f993b9ccac4847f640979): add offline update subcommands
### Debian
- [e2dcbf9](https://github.com/quay/claircore/commit/e2dcbf9914bbb16e00499d2022f3c348603c9da0): fix conditional fetch
### Distlock
- [24c305f](https://github.com/quay/claircore/commit/24c305f14af3c1642022731c442736f8ceaa0e18): implement interface over pgxpool
### Driver
- [3f4d56f](https://github.com/quay/claircore/commit/3f4d56f97e33a74736b8a8aeef557497829876bd): add Configurable interface
### Jsonblob
- [92f3904](https://github.com/quay/claircore/commit/92f3904e738b73d2da3d04f51bbc073100631e6d): add database impostor package
### Libvuln
- [568096b](https://github.com/quay/claircore/commit/568096b68a607d70830d6639f8b93d77aee84faf): refactor updater execution
- [f7426b2](https://github.com/quay/claircore/commit/f7426b20d5ceac18b16a60eeffc82b9b0657a8f3): use new Configurable interfaces
- [b9b5dec](https://github.com/quay/claircore/commit/b9b5dec78425b733485ea063ee958bb70fe499d8): use Executor + UpdateSetFactory
### Log
- [900f3bb](https://github.com/quay/claircore/commit/900f3bb2e48bd2bc158daf6412959830b38f676c): one more attempt at race squashing
### Matcher
- [d51d4c3](https://github.com/quay/claircore/commit/d51d4c38603154a1b8e9a64c1d19d68952f7d3a7): Introduce Remote Matcher interface ([#202](https://github.com/quay/claircore/issues/202))
 -  [#202](https://github.com/quay/claircore/issues/202)### Osrelease
- [ea0ef68](https://github.com/quay/claircore/commit/ea0ef6862330ae59f2c31a795924001d759586f8): fix integration test
### Ovalutil
- [6309553](https://github.com/quay/claircore/commit/6309553805af7d751cd80c3b997d932dff8aebb9): don't record Date in fingerprint if Etag is present
- [c84d73c](https://github.com/quay/claircore/commit/c84d73c603569f8d67570928cec2076ec693a6ab): use modified and etag conditional requests
- [bf06dd5](https://github.com/quay/claircore/commit/bf06dd5b032726cfaa5d079de5bb89d95dd99237): handle "exists" tests better
### Postgres
- [4e8df71](https://github.com/quay/claircore/commit/4e8df713ec5e4fc63fb3e72d30a648b2733dc963): split vulnerability creation into two statements
- [27359db](https://github.com/quay/claircore/commit/27359db7bb7d09e36cf53e654ef48c6aaebf6a1c): remove sqlx usage
### Pyupio
- [096bed5](https://github.com/quay/claircore/commit/096bed5a9e9d9fba573b2c0095c3e228bcee8852): use etag
### Rhel
- [bc4a6f7](https://github.com/quay/claircore/commit/bc4a6f710bb85c013648ecbaa116fd93f8dbb32f): add configuration and manifest caching
- [c3bada8](https://github.com/quay/claircore/commit/c3bada8883e397c791b09fe1cee4032d44ea2468): handle empty cpes
- [65fae38](https://github.com/quay/claircore/commit/65fae38daac3ddf8e3017bbdd90d236a2569ac94): use pulp factory
### Ubuntu
- [d30bf1e](https://github.com/quay/claircore/commit/d30bf1eb46e32533ecc7098ea085a434b0f3dbae): fix conditional fetch
- [c9b6274](https://github.com/quay/claircore/commit/c9b6274a733c93f0a70914cdc16923321387ca39): new updater framework
### Updater
- [ea1a99a](https://github.com/quay/claircore/commit/ea1a99a8eb9a2d694e0c0598e5a9bc67148a4647): add Controller and offline implementation

<a name="v0.0.25"></a>
## [v0.0.25] - 2020-06-08
### Updatediffs
- [a7fce3e](https://github.com/quay/claircore/commit/a7fce3e913d7f46163217a77fc946fbe6776e66a): fix broken query

<a name="v0.0.24"></a>
## [v0.0.24] - 2020-06-01

<a name="v0.0.23"></a>
## [v0.0.23] - 2020-05-26
### Aws
- [79bad1e](https://github.com/quay/claircore/commit/79bad1ee064f662ada65a4110516050770f1a1c6): ensure Close call gets to underlying File
### Cpe
- [ef7ce23](https://github.com/quay/claircore/commit/ef7ce23ac11143af26e771ab3ee2ebb6a763196d): use a structured type for CPEs
### Etc
- [4e73b31](https://github.com/quay/claircore/commit/4e73b31176bcdd93fdbe8cf638172253775b73bb): podman yaml needs volume flag
### Fastesturl
- [59f5f98](https://github.com/quay/claircore/commit/59f5f9874d037ac5462e0312d3cf83c71995a9fb): flaky test hunting
### Indexer
- [11b4676](https://github.com/quay/claircore/commit/11b46764e5455c5d555704c055f8a2e7b0b8c31f): add Configurable interface
### Libindex
- [ac10351](https://github.com/quay/claircore/commit/ac1035164fb4b8727698e0835750835a8edf44dc): use new Configurable interfaces
### Ubuntu
- [92a7a15](https://github.com/quay/claircore/commit/92a7a15024f8af5a158e49bd14796ba0434a927b): remove unused variables

<a name="v0.0.22"></a>
## [v0.0.22] - 2020-05-01
### Claircore
- [d04ad4c](https://github.com/quay/claircore/commit/d04ad4c7b03b7fced4b39e808798514f68219478): make Severity a proper enum
### Docs
- [b5d84c0](https://github.com/quay/claircore/commit/b5d84c0204d4be489d8f156d0f04e23804755dc0): mention pyupio updater
### Makefile
- [373f1cd](https://github.com/quay/claircore/commit/373f1cde4cbd3c91ef72753b722861552b3183b8): use podman play for podman env

<a name="v0.0.21"></a>
## [v0.0.21] - 2020-04-30
### Postgres
- [7f42a18](https://github.com/quay/claircore/commit/7f42a18e0da1b53a035c87f65dc97b3aa26596e4): defer after checking error

<a name="v0.0.20"></a>
## [v0.0.20] - 2020-04-17

<a name="v0.0.19"></a>
## [v0.0.19] - 2020-04-03
### Migrations
- [e76ed28](https://github.com/quay/claircore/commit/e76ed28787738ee190b9de814313c6f0536b2d51): improve extension error reporting

<a name="v0.0.18"></a>
## [v0.0.18] - 2020-03-12
### Fastesturl
- [859a311](https://github.com/quay/claircore/commit/859a31197e69c37520e2cafa18098b290144586a): deflake the test
### Integration
- [7a30aaa](https://github.com/quay/claircore/commit/7a30aaad50b86c3849fef4375b62949fd7c00eca): load uuid-ossp before dropping privileges
### Libvuln
- [486e6a6](https://github.com/quay/claircore/commit/486e6a6f1b6d94fb93f9135f0bde5b05a0107399): use new Updater interface
### Migrations
- [a6aaa82](https://github.com/quay/claircore/commit/a6aaa8278d6d0e44e2ea9efd70205c846fbcdb91): rewrite schema to be operation-based
### Pkgconfig
- [e784bd8](https://github.com/quay/claircore/commit/e784bd8f679a45749ffebb981cf69df708acc587): add pkg-config scanner
### Postgres
- [e3fa032](https://github.com/quay/claircore/commit/e3fa032b9149d5063a391fdb24716fc480ababc8): implement new Updater interface
### Reduce
- [1010855](https://github.com/quay/claircore/commit/10108557e2a3ef89cb9d60ec2d51518cebbbebca): pass all instances of a layer to be fetched to the fetcher
### Updater
- [41860d4](https://github.com/quay/claircore/commit/41860d427ebc344c0cd6fdc5323db61fd341e4cb): use new Updater interface
### Vulnstore
- [3873d45](https://github.com/quay/claircore/commit/3873d45f6ddcf5664b6c083f747ac1da13a94931): update Updater interface

<a name="v0.0.17"></a>
## [v0.0.17] - 2020-03-05

<a name="v0.0.16"></a>
## [v0.0.16] - 2020-02-28
### Alpine
- [e800a02](https://github.com/quay/claircore/commit/e800a02a66bcf9787ae0249110613446c7329925): don't choke on very large package entries
### Cctool
- [ae4be45](https://github.com/quay/claircore/commit/ae4be45aff5e6e92906b29e8539120e6e776704f): dump vulnerability report with dump flag
### Claircore
- [c99a5c8](https://github.com/quay/claircore/commit/c99a5c81795384467cdf084e9e0dd399a679b6bd): add Version and Range types
### Controller
- [f6587f8](https://github.com/quay/claircore/commit/f6587f843e38d711cb6dd814fa5421981afa1dad): record manifest before using in logger
### Driver
- [e2d3d34](https://github.com/quay/claircore/commit/e2d3d3401a8b1b623ef29849bdc41543d822f3b5): add optional interface for database filtering
### Fetcher
- [ee72da6](https://github.com/quay/claircore/commit/ee72da6f22bfae606cf0f0dd7f425e828e1408e1): handle servers returning binary/octect-stream
### Indexer, Vulnstore
- [062bf90](https://github.com/quay/claircore/commit/062bf902e2c0bb48a7471038b99dfac89015019e): use version and range in the database
- [f8d17dc](https://github.com/quay/claircore/commit/f8d17dceb95fd28195454f25e38e6f448fe3a2de): database connection correctness
### Libindex
- [655312e](https://github.com/quay/claircore/commit/655312e246684905c90c1d8567547edc3ec135b3): add python to defaults
### Libvuln
- [4e038fb](https://github.com/quay/claircore/commit/4e038fb886cc1b9d67636a5304378457c2a1fb00): add python to defaults
### Makefile
- [116d63f](https://github.com/quay/claircore/commit/116d63fca2f7ee54a86de2c63b61004a34ac1dd5): use variables in podman targets
### Matcher
- [b72885d](https://github.com/quay/claircore/commit/b72885dece5cc37bc08d23515fad152122e31885): use db filtering in controller
### Migrations
- [a5b9f0d](https://github.com/quay/claircore/commit/a5b9f0dd7a2d037e26731d746396de374e85a23a): add version representation to database
### Pep440
- [4436de2](https://github.com/quay/claircore/commit/4436de2f86e59a5f0d521d49eb8b5e8156d957ee): add package supporting PEP-440 versioning
### Python
- [3f6abba](https://github.com/quay/claircore/commit/3f6abba1745a184f1ed5a3fbd59e966ce179ab0b): add python package scanner
### Pyupio
- [1ada901](https://github.com/quay/claircore/commit/1ada90173f5f48226b7270b629e3735e28df2ef6): add pyup.io updater
### Rhel
- [ad81962](https://github.com/quay/claircore/commit/ad819628990ec96d382c5325c7e1748a8dfd3e53): check before dereferencing record.Distribution
### Rpm
- [75ef273](https://github.com/quay/claircore/commit/75ef2737fd066e34646c774b3220d2c6710e5133): don't extract whiteout files
### Test
- [b9c767b](https://github.com/quay/claircore/commit/b9c767bef8f62439b9073dc242e979903fc84e6c): add common package scanner machinery

<a name="v0.0.15"></a>
## [v0.0.15] - 2020-03-03
### Ovalutil
- [a57487f](https://github.com/quay/claircore/commit/a57487fee6d9991ceafbdd63640365796d5fff30): correctness fixes

<a name="v0.0.14"></a>
## [v0.0.14] - 2020-02-10
### All
- [f47acf1](https://github.com/quay/claircore/commit/f47acf1c68040ab3035e1fb017c35d6b2bd050e2): unify digest representation
 - closes [#113](https://github.com/quay/claircore/issues/113)- [f2dcacc](https://github.com/quay/claircore/commit/f2dcacc326a208eb9a80c93dcb652592511dfa5d): logging consistency pass
### Cctool
- [2b3bb44](https://github.com/quay/claircore/commit/2b3bb445d46e2fcd07e5cb2ac8d7079bbe0a06f1): add "manifest" subcommand
### Docs
- [dbd6ba2](https://github.com/quay/claircore/commit/dbd6ba2edfd85e6fb4b4b0ed0374dc15d66fe43a): use mdBook config file instead of weird symlinks
### Feat
- [2030a92](https://github.com/quay/claircore/commit/2030a929b0cc259d1a59159d5e53d6b51d6d5cbc): add jUnit reports to cctool
### Postgres
- [1bec5c9](https://github.com/quay/claircore/commit/1bec5c952bdb650e3b0a7856e7eeba01d75c967f): retrieve updater informaition

<a name="v0.0.13"></a>
## [v0.0.13] - 2020-01-15
### All
- [7d6e79b](https://github.com/quay/claircore/commit/7d6e79bf2515a7ce0f13178ba4444db11ddd7548): use bigserials in the database
### Cctool
- [8c1e827](https://github.com/quay/claircore/commit/8c1e827b7f205934b8fd2c08f329a024cf790984): update with datastructure changes and index call semantics
### Libindex
- [064e0f6](https://github.com/quay/claircore/commit/064e0f673d0d87585ded6076de4836f9df72ea60): add location header
### Libvuln
- [09b75dd](https://github.com/quay/claircore/commit/09b75ddd2ab41f955490446c6df94323e632495a): propagate initilization context
### Makefile
- [94b70f2](https://github.com/quay/claircore/commit/94b70f203d94d4b3404a7d0e9bcaa3ba7d3fe60f): add mdbook target
### Postgres
- [932cece](https://github.com/quay/claircore/commit/932cece306d95a1f50145aeb666c22c84c1d300a): remove use of context.Background
- [e453f95](https://github.com/quay/claircore/commit/e453f95f3e12f3619f327e992b5e6a10e612abfd): discard vulnerabilites with no package
- [cbf05ac](https://github.com/quay/claircore/commit/cbf05ac4013ffe4ba04d07c37a44d82b8aaf0092): discard empty-named packages

<a name="v0.0.12"></a>
## [v0.0.12] - 2020-01-10

<a name="v0.0.11"></a>
## [v0.0.11] - 2020-01-09

<a name="v0.0.10"></a>
## [v0.0.10] - 2020-01-08
### All
- [f7791a0](https://github.com/quay/claircore/commit/f7791a0fc7d9bf3e0d9168b5f1dac87ea9da4c72): remove context.Background usage in test
### Cctool
- [c7918bf](https://github.com/quay/claircore/commit/c7918bf7ba3d0cb9972c33bd2775efecfffd021b): generate storage URLs based on registry manifest
### Etc
- [501f4dd](https://github.com/quay/claircore/commit/501f4ddf8a402698ac9ca0906c68ee240407963a): update Dockerfile ([#92](https://github.com/quay/claircore/issues/92))
 -  [#92](https://github.com/quay/claircore/issues/92)### Fetcher
- [1a04296](https://github.com/quay/claircore/commit/1a04296e4ea41deb39b13528a7f56ec1d7df7780): flush buffer to disk
### Libindex
- [8a5a18a](https://github.com/quay/claircore/commit/8a5a18affde1a7cbe55cc795cf121c99c98b2dfd): add state endpoint and merge http handler
- [5195457](https://github.com/quay/claircore/commit/519545705e660439e1275b95bbe1d1a19309a529): add State method
### Libindexhttp
- [38bfe2d](https://github.com/quay/claircore/commit/38bfe2d420a187a856e36fe368ef63cd53f64216): propigate context from main
### Log
- [8788c7d](https://github.com/quay/claircore/commit/8788c7de653d855b6c73d03fc4d9986db8bfb049): bound log prints to a Context
### Osrelease
- [bb74bc1](https://github.com/quay/claircore/commit/bb74bc16a4abd03b9df7abaf21595ea8701e85d6): don't unconditionally defer
### Postrges
- [4c9b86f](https://github.com/quay/claircore/commit/4c9b86f5a36ee71d4488005cc6052d2751744078): fix test copy-paste errors

<a name="v0.0.9"></a>
## [v0.0.9] - 2019-12-10

<a name="v0.0.8"></a>
## [v0.0.8] - 2019-12-10
### All
- [57ffc13](https://github.com/quay/claircore/commit/57ffc13af1a741e192bd22af81e332468991dcc4): regroup imports consistently
### Cctool
- [250d8da](https://github.com/quay/claircore/commit/250d8da4dda7151246aff90f5db2ab5d5443a19b): add a tool for interacting with claircore directly
### Claircore
- [60789e7](https://github.com/quay/claircore/commit/60789e727d960395b522bb4fd1caf32ad01616ce): add annotations to generate slighty smaller json
### Libvuln
- [9ae9ed9](https://github.com/quay/claircore/commit/9ae9ed911a6ff8e2b8af40772e64506ad8031736): add rpm matcher to defaults
### Libvulnhttp
- [dff4316](https://github.com/quay/claircore/commit/dff43169dfab7f3d5183614c47f0b2e0c862ac02): wire in additional debugging logs
### Makefile
- [a8bf8be](https://github.com/quay/claircore/commit/a8bf8bebd8f34579aeb3caf69e449f09d274864a): have podman remove volumes
### Osrelease
- [d5cfb06](https://github.com/quay/claircore/commit/d5cfb0673cb09454fa476140812d8762fa84fcfa): add RHEL-alike hack
- [8bd23ff](https://github.com/quay/claircore/commit/8bd23ffe66c3e3825830fa827d8ee31227849e16): add logging statements
### Osrelease, Ovalutil
- [cec88d1](https://github.com/quay/claircore/commit/cec88d1de39e77228e8636b272146c51792e0491): normalize CPEs
### Ovalutil
- [e650898](https://github.com/quay/claircore/commit/e650898e1e6da4d8e31ae6f000611f59b37885f9): add cpe information to packages
### Postgres
- [37fccbb](https://github.com/quay/claircore/commit/37fccbb5f4667ba0a530ac7a33292f6e171c89b2): use different names for different prepared statements
- [1e8c519](https://github.com/quay/claircore/commit/1e8c519c6fe0444940b010ec7d1ec3fb8cc64a05): handle driver.Package(Source)Name arguments
- [5db1ffe](https://github.com/quay/claircore/commit/5db1ffe1dd4925270936d66e1cb173f383216589): check query builder error
### Rhel
- [99a2379](https://github.com/quay/claircore/commit/99a2379de49a78911179f376e488793129c94c2a): add matcher test
- [7087457](https://github.com/quay/claircore/commit/7087457f7f756f8a37fec6538e47113337c7781b): add matcher
### Rpm
- [e4cd783](https://github.com/quay/claircore/commit/e4cd783b4d5021d93cbf59d760744f01bb6d57e0): prevent infinite loop on read error
- [383e108](https://github.com/quay/claircore/commit/383e108da0789c2d3f8950d96adfcfb83d0c6564): fix package scanner test
### Test
- [e894054](https://github.com/quay/claircore/commit/e8940545b8604ed3c38babd951dc283d111333f8): add disk-based updater

<a name="v0.0.7"></a>
## [v0.0.7] - 2019-12-02

<a name="v0.0.6"></a>
## [v0.0.6] - 2019-11-27
### Fetcher
- [0c4072c](https://github.com/quay/claircore/commit/0c4072cb457137ef172b112327b9107b03548e94): check error before defer
### Rpm
- [6fc8d83](https://github.com/quay/claircore/commit/6fc8d831d6da80b11fa94fbb7252118fdc02e825): exclude dev directory

<a name="v0.0.5"></a>
## [v0.0.5] - 2019-11-19

<a name="v0.0.4"></a>
## [v0.0.4] - 2019-11-15
### All
- [6583cf2](https://github.com/quay/claircore/commit/6583cf2982d2314091fb2664f6e609e7eddc0882): add license and dco
- [d55da4c](https://github.com/quay/claircore/commit/d55da4c6844fb093c75a121d27ed992f3ed2bfaf): remove use of "log" package
### Claircore
- [50d7a96](https://github.com/quay/claircore/commit/50d7a96704082f959a6a17df66cae0c23fe8a828): bump goval-parser version
### Integration
- [01ea77c](https://github.com/quay/claircore/commit/01ea77c19485fe2a18ee3fb9269ceeeb11f9fc1c): add database test harness
### Ovalutil
- [d4cc8d0](https://github.com/quay/claircore/commit/d4cc8d09453685f59e413629ff55596f3ab49cca): attach detected dist to vulns
### Updater
- [13ce92c](https://github.com/quay/claircore/commit/13ce92ca5f556025f152cb864628b085044e88b7): use blocking call

<a name="v0.0.3"></a>
## [v0.0.3] - 2019-10-04
### Go.Mod
- [267126b](https://github.com/quay/claircore/commit/267126bd088d0c728a1447b71c02f89ef1ffecc4): update goval-parser version
### Oracle
- [8f38e72](https://github.com/quay/claircore/commit/8f38e7296f3dbd8852202089b6a41de23a83f38e): rework to year-wise databases
### Ovalutil
- [fa5ca19](https://github.com/quay/claircore/commit/fa5ca19281c5eb6a8ec0eb983804a4819dff3f80): rename `oval` package and add common rpminfo functions
### Postgres
- [f5c130a](https://github.com/quay/claircore/commit/f5c130a03215fd973e67c19276b8a2dd0bda5fc8): db batch fix
### Suse
- [c03f5a1](https://github.com/quay/claircore/commit/c03f5a17b04dd16edd30cbf2dc58e1e1b0fa4396): add suse updater

<a name="v0.0.2"></a>
## [v0.0.2] - 2019-10-03
### Amazon
- [2938b67](https://github.com/quay/claircore/commit/2938b67a53e22570fa27b70ae419cfe00f3dba95): add amazon updater
### Oracle
- [7d434c4](https://github.com/quay/claircore/commit/7d434c400aa483dcfca5dddf428f99e5e588440c): add Oracle Linux oval updater

<a name="v0.0.1"></a>
## v0.0.1 - 2019-09-30
### All
- [bf7f5a3](https://github.com/quay/claircore/commit/bf7f5a309d44b79c8e6fca10d62ba11c5bc4896b): move to pgx/v4
### Distlock/Postgres
- [d362b3e](https://github.com/quay/claircore/commit/d362b3e82c82c36c9b04fcbb322096db17f2f3af): convert key to int64
- [b290260](https://github.com/quay/claircore/commit/b290260c56ff2f5b037b734ed11858998d52974c): hash input key
### Driver
- [bce0ecf](https://github.com/quay/claircore/commit/bce0ecfa50dc80921226923c10fad870ba507899): create libvuln/driver package
### Integration
- [ebc1eea](https://github.com/quay/claircore/commit/ebc1eea4239a34bceb5f1c46cd6e969f42b66c27): add test/integration package
### Makefile
- [a29d899](https://github.com/quay/claircore/commit/a29d89930fdacf8317b697e63097062e41313e31): have docker-compose populate and use a vendor directory
- [b97b97e](https://github.com/quay/claircore/commit/b97b97e03b969c21785bebeb9217593df85aa101): have podman targets populate and use a vendor directory
- [480d4e5](https://github.com/quay/claircore/commit/480d4e51e111d32e40f2da6be3e0f93676311b1b): add some podman
### Rhel
- [41f947f](https://github.com/quay/claircore/commit/41f947fcdbf816317b0f104995dc375273def30c): add rhel vulnerability updater
### Scanner
- [303150c](https://github.com/quay/claircore/commit/303150c5b376b20fa28e0efb5e8fe83d9719bc57): add missed contexts
### Updater
- [62abdfa](https://github.com/quay/claircore/commit/62abdfab61d5c3594650e229c82105e3ffed557f): don't expect to call Close on error paths
### Vendor
- [cbd3610](https://github.com/quay/claircore/commit/cbd3610156abf9ee2840712ff84193b0554685c2): remove vendor folder
### Vulnstore
- [4c53d16](https://github.com/quay/claircore/commit/4c53d16de6f06d4040b8f071940f279fae15d668): add context.Context to interfaces
### Pull Requests
- Merge pull request [#28](https://github.com/quay/claircore/issues/28) from quay/louis/dist-lock-fix
- Merge pull request [#27](https://github.com/quay/claircore/issues/27) from quay/louis/unique-constraint-fix
- Merge pull request [#9](https://github.com/quay/claircore/issues/9) from quay/docker-compose
- Merge pull request [#12](https://github.com/quay/claircore/issues/12) from quay/code-owners
- Merge pull request [#6](https://github.com/quay/claircore/issues/6) from quay/debian-support
- Merge pull request [#5](https://github.com/quay/claircore/issues/5) from quay/scanner-data-model-docs
- Merge pull request [#3](https://github.com/quay/claircore/issues/3) from quay/documentation


[Unreleased]: https://github.com/quay/claircore/compare/v0.4.2...HEAD
[v0.4.2]: https://github.com/quay/claircore/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/quay/claircore/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/quay/claircore/compare/v0.3.3...v0.4.0
[v0.3.3]: https://github.com/quay/claircore/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/quay/claircore/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/quay/claircore/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/quay/claircore/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/quay/claircore/compare/v0.1.25...v0.2.0
[v0.1.25]: https://github.com/quay/claircore/compare/v0.1.24...v0.1.25
[v0.1.24]: https://github.com/quay/claircore/compare/v0.1.23...v0.1.24
[v0.1.23]: https://github.com/quay/claircore/compare/v0.1.22...v0.1.23
[v0.1.22]: https://github.com/quay/claircore/compare/v0.1.21...v0.1.22
[v0.1.21]: https://github.com/quay/claircore/compare/v0.1.20...v0.1.21
[v0.1.20]: https://github.com/quay/claircore/compare/v0.1.19...v0.1.20
[v0.1.19]: https://github.com/quay/claircore/compare/v0.1.18...v0.1.19
[v0.1.18]: https://github.com/quay/claircore/compare/v0.1.17...v0.1.18
[v0.1.17]: https://github.com/quay/claircore/compare/v0.1.16...v0.1.17
[v0.1.16]: https://github.com/quay/claircore/compare/v0.1.15...v0.1.16
[v0.1.15]: https://github.com/quay/claircore/compare/v0.1.14...v0.1.15
[v0.1.14]: https://github.com/quay/claircore/compare/v0.1.13...v0.1.14
[v0.1.13]: https://github.com/quay/claircore/compare/v0.1.12...v0.1.13
[v0.1.12]: https://github.com/quay/claircore/compare/v0.1.11...v0.1.12
[v0.1.11]: https://github.com/quay/claircore/compare/v0.1.10...v0.1.11
[v0.1.10]: https://github.com/quay/claircore/compare/v0.1.9...v0.1.10
[v0.1.9]: https://github.com/quay/claircore/compare/v0.1.8...v0.1.9
[v0.1.8]: https://github.com/quay/claircore/compare/v0.1.7...v0.1.8
[v0.1.7]: https://github.com/quay/claircore/compare/v0.1.6...v0.1.7
[v0.1.6]: https://github.com/quay/claircore/compare/v0.1.5...v0.1.6
[v0.1.5]: https://github.com/quay/claircore/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/quay/claircore/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/quay/claircore/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/quay/claircore/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/quay/claircore/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/quay/claircore/compare/v0.0.25...v0.1.0
[v0.0.25]: https://github.com/quay/claircore/compare/v0.0.24...v0.0.25
[v0.0.24]: https://github.com/quay/claircore/compare/v0.0.23...v0.0.24
[v0.0.23]: https://github.com/quay/claircore/compare/v0.0.22...v0.0.23
[v0.0.22]: https://github.com/quay/claircore/compare/v0.0.21...v0.0.22
[v0.0.21]: https://github.com/quay/claircore/compare/v0.0.20...v0.0.21
[v0.0.20]: https://github.com/quay/claircore/compare/v0.0.19...v0.0.20
[v0.0.19]: https://github.com/quay/claircore/compare/v0.0.18...v0.0.19
[v0.0.18]: https://github.com/quay/claircore/compare/v0.0.17...v0.0.18
[v0.0.17]: https://github.com/quay/claircore/compare/v0.0.16...v0.0.17
[v0.0.16]: https://github.com/quay/claircore/compare/v0.0.15...v0.0.16
[v0.0.15]: https://github.com/quay/claircore/compare/v0.0.14...v0.0.15
[v0.0.14]: https://github.com/quay/claircore/compare/v0.0.13...v0.0.14
[v0.0.13]: https://github.com/quay/claircore/compare/v0.0.12...v0.0.13
[v0.0.12]: https://github.com/quay/claircore/compare/v0.0.11...v0.0.12
[v0.0.11]: https://github.com/quay/claircore/compare/v0.0.10...v0.0.11
[v0.0.10]: https://github.com/quay/claircore/compare/v0.0.9...v0.0.10
[v0.0.9]: https://github.com/quay/claircore/compare/v0.0.8...v0.0.9
[v0.0.8]: https://github.com/quay/claircore/compare/v0.0.7...v0.0.8
[v0.0.7]: https://github.com/quay/claircore/compare/v0.0.6...v0.0.7
[v0.0.6]: https://github.com/quay/claircore/compare/v0.0.5...v0.0.6
[v0.0.5]: https://github.com/quay/claircore/compare/v0.0.4...v0.0.5
[v0.0.4]: https://github.com/quay/claircore/compare/v0.0.3...v0.0.4
[v0.0.3]: https://github.com/quay/claircore/compare/v0.0.2...v0.0.3
[v0.0.2]: https://github.com/quay/claircore/compare/v0.0.1...v0.0.2
