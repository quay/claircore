<a name="unreleased"></a>
## [Unreleased]


<a name="v0.1.9"></a>
## [v0.1.9] - 2020-09-25
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
### Ovalutil
- [a57487f](https://github.com/quay/claircore/commit/a57487fee6d9991ceafbdd63640365796d5fff30): correctness fixes
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


[Unreleased]: https://github.com/quay/claircore/compare/v0.1.9...HEAD
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
[v0.0.17]: https://github.com/quay/claircore/compare/v0.0.15...v0.0.17
[v0.0.15]: https://github.com/quay/claircore/compare/v0.0.16...v0.0.15
[v0.0.16]: https://github.com/quay/claircore/compare/v0.0.14...v0.0.16
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
