package rpmdb

// C.f. rpm's include/rpm/rpmtag.h -- This was done by hand with some editor
// scripts, but there has to be a better way.

import "bytes"

//go:generate -command stringer go run golang.org/x/tools/cmd/stringer
//go:generate stringer -type Tag,Kind

// Tag is the term for the key in the key-value pairs in a Header.
type Tag int32

// Header tags.
const (
	TagInvalid Tag = -1
	_          Tag = 60 + iota
	TagHeaderImage
	TagHeaderSignatures
	TagHeaderImmutable
	TagHeaderRegions

	TagHeaderI18nTable Tag = 100
)

// Signing Tags.
const (
	_tagSigBase Tag = 256 + iota
	TagSigSize
	TagSigLeMD5 // internal, obsolete
	TagSigPGP
	TagSigLeMD5_2 // internal, obsolete
	TagSigMD5
	TagSigGPG
	TagSigGPG5   // internal, obsolete
	TagBadSHA1_1 // internal, obsolete
	TagBadSHA1_2 // internal, obsolete
	TagPubKeys
	TagDSAHeader
	TagRSAHeader
	TagSHA1Header
	TagLongSigSize
	TagLongArchiveSize
	_ // reserved
	TagSHA256Header
	_ // reserved
	_ // reserved
	TagVeritySignatures
	TagVeritySignatureAlgo
)

// General Tags.
const (
	TagName Tag = 1000 + iota
	TagVersion
	TagRelease
	TagEpoch
	TagSummary
	TagDescription
	TagBuildTime
	TagBuildHost
	TagInstallTime
	TagSize
	TagDistribution
	TagVendor
	TagGIF
	TagXPM
	TagLicense
	TagPackager
	TagGroup
	TagChangelog // internal ?
	TagSource
	TagPatch
	TagURL
	TagOS
	TagArch
	TagPreInstall
	TagPostInstall
	TagPreUninstall
	TagPostUninstall
	TagOldFilenames // obsolete
	TagFileSizes
	TagFileStates
	TagFileModes
	TagFileUids // obsolete
	TagFileGids // obsolete
	TagFileRDevs
	TagFileMTimes
	TagFileDigests
	TagFileLinkTos
	TagFileFlags
	TagRoot // internal, obsolete
	TagFileUsername
	TagFileGroupname
	TagExclude   // obsolete
	TagExclusive // obsolete
	TagIcon
	TagSourceRPM
	TagFileVerifyFlags
	TagArchiveSize
	TagProvideName
	TagRequireFlags
	TagRequireName
	TagRequireVersion
	TagNoSource
	TagNoPatch
	TagConflictFlags
	TagConflictName
	TagConflictVersion
	TagDefaultPrefix // internal, deprecated
	TagBuildRoot     // internal, obsolete
	TagInstallPrefix // internal, deprecated
	TagExcludeArch
	TagExcludeOS
	TagExclusiveArch
	TagExclusiveOS
	TagAutoReqProv // internal
	TagRPMVersion
	TagTriggerScripts
	TagTriggerName
	TagTriggerVersion
	TagTriggerFlags
	TagTriggerIndex
	_
	_
	_
	_
	_
	_
	_
	_
	_
	TagVerifyScript
	TagChangelogTime
	TagChangelogName
	TagChangelogText
	TagBrokenMD5 // internal, obsolete
	TagPreReq    // internal
	TagPreInstallProg
	TagPostInstallProg
	TagPreUninstallProg
	TagPostUninstallProg
	TagBuildArchs
	TagObsoleteName
	TagVerifyScriptProg
	TagTriggerScriptProg
	TagDocDir // internal
	TagCookie
	TagFileDevices
	TagFileInodes
	TagFileLangs
	TagPrefixes
	TagInstallPrefixes
	TagTriggerInstall       // internal
	TagTriggerUninstall     // internal
	TagTriggerPostUninstall // internal
	TagAutoReq              // internal
	TagAutoProv             // internal
	TagCapability           // internal, obsolete
	TagSourcePackage
	TagOldOriginalFilenames // internal, obsolete
	TagBuildPreReq          // internal
	TagBuildRequires        // internal
	TagBuildConflicts       // internal
	TagBuildMacros          // internal, unused
	TagProvideFlags
	TagProvideVersion
	TagObsoleteFlags
	TagObsoleteVersion
	TagDirindexes
	TagBasenames
	TagDirnames
	TagOrigDirindexes
	TagOrigBasenames
	TagOrigDirnames
	TagOptFlags
	TagDistURL
	TagPayloadFormat
	TagPayloadCompressor
	TagPayloadFlags
	TagInstallColor
	TagInstallTID
	TagRemoveTID
	TagSHA1RHN     // internal, obsolete
	TagRHNPlatform // internal, obsolete
	TagPlatform
	TagPatchesName    // deprecated, SuSE
	TagPatchesFlags   // deprecated, SuSE
	TagPatchesVersion // deprecated, SuSE
	TagCacheCtime     // internal, obsolete
	TagCachePkgPath   // internal, obsolete
	TagCachePkgSize   // internal, obsolete
	TagCachePkgMtime  // internal, obsolete
	TagFileColors
	TagFileClass
	TagClassDict
	TagFileDependsX
	TagFileDependsN
	TagDependsDict
	TagSourcePkgID
	TagFileContexts // obsolete
	TagFSContexts
	TagREContexts
	TagPolicies
	TagPreTrans
	TagPostTrans
	TagPreTransProg
	TagPostTransProg
	TagDistTag
	TagOldSuggestsName    // obsolete, aka OLDSUGGESTS
	TagOldSuggestsVersion // obsolete
	TagOldSuggestsFlags   // obsolete
	TagOldEnhancesName    // obsolete, aka OLDENHANCES
	TagOldEnhancesVersion // obsolete
	TagOldEnhancesFlags   // obsolete
	TagPriority           // unimplemented
	TagCVSID              // unimplemented, aka SVNID
	TagBLinkPkgID         // unimplemented
	TagBLinkHdrID         // unimplemented
	TagBLinkNEVRA         // unimplemented
	TagFLinkPkgID         // unimplemented
	TagFLinkHdrID         // unimplemented
	TagFLinkNEVRA         // unimplemented
	TagPackageOrigin      // unimplemented
	TagTriggerPreInstall  // internal
	TagBuildSuggests      // internal, unimplemented
	TagBuildEnhances      // internal, unimplemented
	TagScriptStates       // unimplemented
	TagScriptMetrics      // unimplemented
	TagBuildCPUClock      // unimplemented
	TagFileDigestAlgos    // unimplemented
	TagVariants           // unimplemented
	TagXMajor             // unimplemented
	TagXMinor             // unimplemented
	TagRepoTag            // unimplemented
	TagKeywords           // unimplemented
	TagBuildPlatforms     // unimplemented
	TagPackageColor       // unimplemented
	TagPackagePrefColor   // unimplemented
	TagXAttrsDict         // unimplemented
	TagFileXAttrsx        // unimplemented
	TagDepAttrsDict       // unimplemented
	TagConflictAttrsX     // unimplemented
	TagObsoleteAttrsX     // unimplemented
	TagProvideAttrsX      // unimplemented
	TagRequireAttrsX      // unimplemented
	TagBuildProvides      // unimplemented
	TagBuildObsoletes     // unimplemented
	TagDbInstance         // extension
	TagNVRA               // extension
)

// Tags 1997 - 4999 reserved

// General Tags, second block.
const (
	TagFilenames     Tag = 5000 + iota // extension
	TagFileProvide                     // extension
	TagFileRequire                     // extension
	TagFsNames                         // unimplemented
	TagFsFizes                         // unimplemented
	TagTriggerConds                    // extension
	TagTriggerType                     // extension
	TagOrigFileNames                   // extension
	TagLongFileSizes
	TagLongSize
	TagFileCaps
	TagFileDigestAlgo
	TagBugURL
	TagEVR         // extension
	TagNVR         // extension
	TagNEVR        // extension
	TagNEVRA       // extension
	TagHeaderColor // extension
	TagVerbose     // extension
	TagEpochNum    // extension
	TagPreInstallFlags
	TagPostInstallFlags
	TagPreUninstallFlags
	TagPostUninstallFlags
	TagPreTransFlags
	TagPostTransFlags
	TagVerifyScriptFlags
	TagTriggerScriptFlags
	_              // Infuriating blank tag
	TagCollections // unimplemented
	TagPolicyNames
	TagPolicyTypes
	TagPolicyTypesIndexes
	TagPolicyFlags
	TagVCS
	TagOrderName
	TagOrderVersion
	TagOrderFlags
	TagMSSFManifest  // unimplemented
	TagMSSFDomain    // unimplemented
	TagInstFilenames // extension
	TagRequireNEVRS  // extension
	TagProvideNEVRS  // extension
	TagObsoleteNEVRS // extension
	TagConflictNEVRS // extension
	TagFileNLinks    // extension
	TagRecommendName // aka RECOMMENDS
	TagRecommendVersion
	TagRecommendFlags
	TagSuggestName // aka SUGGESTS
	TagSuggestVersion
	TagSuggestFlags
	TagSupplementName // aka SUPPLEMENTS
	TagSupplementVersion
	TagSupplementFlags
	TagEnhanceName // aka ENHANCES
	TagEnhanceVersion
	TagEnhanceFlags
	TagRecommendNEVRS  // extension
	TagSuggestNEVRS    // s[] extension
	TagSupplementNEVRS // s[] extension
	TagEnhanceNEVRS    // s[] extension
	TagEncoding
	TagFileTriggerInstall       // internal
	TagFileTriggerUninstall     // internal
	TagFileTriggerPostUninstall // internal
	TagFileTriggerScripts
	TagFileTriggerScriptProg
	TagFileTriggerScriptFlags
	TagFileTriggerName
	TagFileTriggerIndex
	TagFileTriggerVersion
	TagFileTriggerFlags
	TagTransFileTriggerInstall       // internal
	TagTransFileTriggerUninstall     // internal
	TagTransFileTriggerPostUninstall // internal
	TagTransFileTriggerScripts
	TagTransFileTriggerScriptProg
	TagTransFileTriggerScriptFlags
	TagTransFileTriggerName
	TagTransFileTriggerIndex
	TagTransFileTriggerVersion
	TagTransFileTriggerFlags
	TagRemovePathPostFixes // internal
	TagFileTriggerPriorities
	TagTransFileTriggerPriorities
	TagFileTriggerConds      // extension
	TagFileTriggerType       // extension
	TagTransFileTriggerConds // extension
	TagTransFileTriggerType  // extension
	TagFileSignatures
	TagFileSignatureLength
	TagPayloadDigest
	TagPayloadDigestAlgo
	TagAutoInstalled //  reservation (unimplemented)
	TagIdentity      //  reservation (unimplemented)
	TagModularityLabel
	TagPayloadDigestAlt
	TagArchSuffix
)

// Stealing a trick from codegen to assert some values.
func _() {
	var x [1]struct{}
	// These are the ends of all the contiguous ranges.
	_ = x[TagVeritySignatureAlgo-(_tagSigBase+21)]
	_ = x[TagTriggerIndex-1069]
	_ = x[TagNVRA-1196]
	_ = x[TagTriggerScriptFlags-5027]
	_ = x[TagPayloadDigestAlt-5097]
}

// Kind is the Kind of data stored in a given Tag.
type Kind uint32

// Tag data Types.
const (
	TypeNull Kind = iota
	TypeChar
	TypeInt8
	TypeInt16
	TypeInt32
	TypeInt64
	TypeString
	TypeBin
	TypeStringArray
	TypeI18nString

	TypeRegionTag = TypeBin
	TypeMin       = TypeChar
	TypeMax       = TypeI18nString
)

func (t Kind) len(ct int, data []byte) (l int) {
	switch t {
	case TypeString:
		if ct != 1 {
			return -1
		}
		fallthrough
	case TypeStringArray:
		fallthrough
	case TypeI18nString:
		bs := bytes.SplitAfterN(data, []byte{0o0}, ct+1)
		for _, s := range bs[:len(bs)-1] {
			l += len(s)
		}
	default:
		if typeSizes[t] == -1 {
			return -1
		}
		l = typeSizes[(t&0xf)] * ct
		if l < 0 || len(data) < l {
			return -1
		}
	}
	return l
}

func (t Kind) alignment() int32 {
	switch t {
	case TypeNull, TypeChar, TypeInt8, TypeString, TypeBin, TypeStringArray, TypeI18nString:
		return 1
	case TypeInt16:
		return 2
	case TypeInt32:
		return 4
	case TypeInt64:
		return 8
	default:
	}
	panic("programmer error: unaligned type?: " + t.String())
}

func (t Kind) class() (c class) {
	switch t {
	case TypeNull:
		c = classNull
	case TypeChar, TypeInt8, TypeInt16, TypeInt32, TypeInt64:
		c = classNumeric
	case TypeString, TypeStringArray, TypeI18nString:
		c = classString
	case TypeBin:
		c = classBinary
	default:
		panic("programmer error: classless type?: " + t.String())
	}
	return c
}

// Class is the type class of a Type.
type class uint32

// Typeclasses.
const (
	classNull class = iota
	classNumeric
	classString
	classBinary
)

// This is keyed by the above types.
var typeSizes = [...]int{
	0,
	1,
	1,
	2,
	4,
	8,
	-1,
	1,
	-1,
	-1,
}

// ReturnType is used in the tag lookup table.
type returnType uint32

// Valid returnTypes.
const (
	returnAny     returnType = 0
	returnScalar  returnType = 0x00010000
	returnArray   returnType = 0x00020000
	returnMapping returnType = 0x00040000
	returnMask    returnType = 0xffff0000
)
