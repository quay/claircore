package sqlite

// C.f. rpm's include/rpm/rpmtag.h -- This was done by hand with some editor
// scripts, but there has to be a better way.

import "bytes"

//go:generate stringer -type tag,kind

// tag is the term for the key in the key-value pairs in a Header.
type tag int32

// Header tags.
const (
	_ tag = 60 + iota
	tagHeaderImage
	tagHeaderSignatures
	tagHeaderImmutable
	tagHeaderRegions

	tagHeaderI18nTable tag = 100
)

// Signing Tags.
const (
	_tagSigBase tag = 256 + iota
	tagSigSize
	tagSigLeMD5 // internal, obsolete
	tagSigPGP
	tagSigLeMD5_2 // internal, obsolete
	tagSigMD5
	tagSigGPG
	tagSigGPG5   // internal, obsolete
	tagBadSHA1_1 // internal, obsolete
	tagBadSHA1_2 // internal, obsolete
	tagPubKeys
	tagDSAHeader
	tagRSAHeader
	tagSHA1Header
	tagLongSigSize
	tagLongArchiveSize
	_ // reserved
	tagSHA256Header
	_ // reserved
	_ // reserved
	tagVeritySignatures
	tagVeritySignatureAlgo
)

// General Tags.
const (
	tagName tag = 1000 + iota
	tagVersion
	tagRelease
	tagEpoch
	tagSummary
	tagDescription
	tagBuildTime
	tagBuildHost
	tagInstallTime
	tagSize
	tagDistribution
	tagVendor
	tagGIF
	tagXPM
	tagLicense
	tagPackager
	tagGroup
	tagChangelog // internal ?
	tagSource
	tagPatch
	tagURL
	tagOS
	tagArch
	tagPreInstall
	tagPostInstall
	tagPreUninstall
	tagPostUninstall
	tagOldFilenames // obsolete
	tagFileSizes
	tagFileStates
	tagFileModes
	tagFileUids // obsolete
	tagFileGids // obsolete
	tagFileRDevs
	tagFileMTimes
	tagFileDigests
	tagFileLinkTos
	tagFileFlags
	tagRoot // internal, obsolete
	tagFileUsername
	tagFileGroupname
	tagExclude   // obsolete
	tagExclusive // obsolete
	tagIcon
	tagSourceRPM
	tagFileVerifyFlags
	tagArchiveSize
	tagProvideName
	tagRequireFlags
	tagRequireName
	tagRequireVersion
	tagNoSource
	tagNoPatch
	tagConflictFlags
	tagConflictName
	tagConflictVersion
	tagDefaultPrefix // internal, deprecated
	tagBuildRoot     // internal, obsolete
	tagInstallPrefix // internal, deprecated
	tagExcludeArch
	tagExcludeOS
	tagExclusiveArch
	tagExclusiveOS
	tagAutoReqProv // internal
	tagRPMVersion
	tagTriggerScripts
	tagTriggerName
	tagTriggerVersion
	tagTriggerFlags
	tagTriggerIndex
	_
	_
	_
	_
	_
	_
	_
	_
	_
	tagVerifyScript
	tagChangelogTime
	tagChangelogName
	tagChangelogText
	tagBrokenMD5 // internal, obsolete
	tagPreReq    // internal
	tagPreInstallProg
	tagPostInstallProg
	tagPreUninstallProg
	tagPostUninstallProg
	tagBuildArchs
	tagObsoleteName
	tagVerifyScriptProg
	tagTriggerScriptProg
	tagDocDir // internal
	tagCookie
	tagFileDevices
	tagFileInodes
	tagFileLangs
	tagPrefixes
	tagInstallPrefixes
	tagTriggerInstall       // internal
	tagTriggerUninstall     // internal
	tagTriggerPostUninstall // internal
	tagAutoReq              // internal
	tagAutoProv             // internal
	tagCapability           // internal, obsolete
	tagSourcePackage
	tagOldOriginalFilenames // internal, obsolete
	tagBuildPreReq          // internal
	tagBuildRequires        // internal
	tagBuildConflicts       // internal
	tagBuildMacros          // internal, unused
	tagProvideFlags
	tagProvideVersion
	tagObsoleteFlags
	tagObsoleteVersion
	tagDirindexes
	tagBasenames
	tagDirnames
	tagOrigDirindexes
	tagOrigBasenames
	tagOrigDirnames
	tagOptFlags
	tagDistURL
	tagPayloadFormat
	tagPayloadCompressor
	tagPayloadFlags
	tagInstallColor
	tagInstallTID
	tagRemoveTID
	tagSHA1RHN     // internal, obsolete
	tagRHNPlatform // internal, obsolete
	tagPlatform
	tagPatchesName    // deprecated, SuSE
	tagPatchesFlags   // deprecated, SuSE
	tagPatchesVersion // deprecated, SuSE
	tagCacheCtime     // internal, obsolete
	tagCachePkgPath   // internal, obsolete
	tagCachePkgSize   // internal, obsolete
	tagCachePkgMtime  // internal, obsolete
	tagFileColors
	tagFileClass
	tagClassDict
	tagFileDependsX
	tagFileDependsN
	tagDependsDict
	tagSourcePkgID
	tagFileContexts // obsolete
	tagFSContexts
	tagREContexts
	tagPolicies
	tagPreTrans
	tagPostTrans
	tagPreTransProg
	tagPostTransProg
	tagDistTag
	tagOldSuggestsName    // obsolete, aka OLDSUGGESTS
	tagOldSuggestsVersion // obsolete
	tagOldSuggestsFlags   // obsolete
	tagOldEnhancesName    // obsolete, aka OLDENHANCES
	tagOldEnhancesVersion // obsolete
	tagOldEnhancesFlags   // obsolete
	tagPriority           // unimplemented
	tagCVSID              // unimplemented, aka SVNID
	tagBLinkPkgID         // unimplemented
	tagBLinkHdrID         // unimplemented
	tagBLinkNEVRA         // unimplemented
	tagFLinkPkgID         // unimplemented
	tagFLinkHdrID         // unimplemented
	tagFLinkNEVRA         // unimplemented
	tagPackageOrigin      // unimplemented
	tagTriggerPreInstall  // internal
	tagBuildSuggests      // internal, unimplemented
	tagBuildEnhances      // internal, unimplemented
	tagScriptStates       // unimplemented
	tagScriptMetrics      // unimplemented
	tagBuildCPUClock      // unimplemented
	tagFileDigestAlgos    // unimplemented
	tagVariants           // unimplemented
	tagXMajor             // unimplemented
	tagXMinor             // unimplemented
	tagRepoTag            // unimplemented
	tagKeywords           // unimplemented
	tagBuildPlatforms     // unimplemented
	tagPackageColor       // unimplemented
	tagPackagePrefColor   // unimplemented
	tagXAttrsDict         // unimplemented
	tagFileXAttrsx        // unimplemented
	tagDepAttrsDict       // unimplemented
	tagConflictAttrsX     // unimplemented
	tagObsoleteAttrsX     // unimplemented
	tagProvideAttrsX      // unimplemented
	tagRequireAttrsX      // unimplemented
	tagBuildProvides      // unimplemented
	tagBuildObsoletes     // unimplemented
	tagDbInstance         // extension
	tagNVRA               // extension
)

// Tags 1997 - 4999 reserved

// General Tags, second block.
const (
	tagFilenames     tag = 5000 + iota // extension
	tagFileProvide                     // extension
	tagFileRequire                     // extension
	tagFsNames                         // unimplemented
	tagFsFizes                         // unimplemented
	tagTriggerConds                    // extension
	tagTriggerType                     // extension
	tagOrigFileNames                   // extension
	tagLongFileSizes
	tagLongSize
	tagFileCaps
	tagFileDigestAlgo
	tagBugURL
	tagEVR         // extension
	tagNVR         // extension
	tagNEVR        // extension
	tagNEVRA       // extension
	tagHeaderColor // extension
	tagVerbose     // extension
	tagEpochNum    // extension
	tagPreInstallFlags
	tagPostInstallFlags
	tagPreUninstallFlags
	tagPostUninstallFlags
	tagPreTransFlags
	tagPostTransFlags
	tagVerifyScriptFlags
	tagTriggerScriptFlags
	_              // Infuriating blank tag
	tagCollections // unimplemented
	tagPolicyNames
	tagPolicyTypes
	tagPolicyTypesIndexes
	tagPolicyFlags
	tagVCS
	tagOrderName
	tagOrderVersion
	tagOrderFlags
	tagMSSFManifest  // unimplemented
	tagMSSFDomain    // unimplemented
	tagInstFilenames // extension
	tagRequireNEVRS  // extension
	tagProvideNEVRS  // extension
	tagObsoleteNEVRS // extension
	tagConflictNEVRS // extension
	tagFileNLinks    // extension
	tagRecommendName // aka RECOMMENDS
	tagRecommendVersion
	tagRecommendFlags
	tagSuggestName // aka SUGGESTS
	tagSuggestVersion
	tagSuggestFlags
	tagSupplementName // aka SUPPLEMENTS
	tagSupplementVersion
	tagSupplementFlags
	tagEnhanceName // aka ENHANCES
	tagEnhanceVersion
	tagEnhanceFlags
	tagRecommendNEVRS  // extension
	tagSuggestNEVRS    // s[] extension
	tagSupplementNEVRS // s[] extension
	tagEnhanceNEVRS    // s[] extension
	tagEncoding
	tagFileTriggerInstall       // internal
	tagFileTriggerUninstall     // internal
	tagFileTriggerPostUninstall // internal
	tagFileTriggerScripts
	tagFileTriggerScriptProg
	tagFileTriggerScriptFlags
	tagFileTriggerName
	tagFileTriggerIndex
	tagFileTriggerVersion
	tagFileTriggerFlags
	tagTransFileTriggerInstall       // internal
	tagTransFileTriggerUninstall     // internal
	tagTransFileTriggerPostUninstall // internal
	tagTransFileTriggerScripts
	tagTransFileTriggerScriptProg
	tagTransFileTriggerScriptFlags
	tagTransFileTriggerName
	tagTransFileTriggerIndex
	tagTransFileTriggerVersion
	tagTransFileTriggerFlags
	tagRemovePathPostFixes // internal
	tagFileTriggerPriorities
	tagTransFileTriggerPriorities
	tagFileTriggerConds      // extension
	tagFileTriggerType       // extension
	tagTransFileTriggerConds // extension
	tagTransFileTriggerType  // extension
	tagFileSignatures
	tagFileSignatureLength
	tagPayloadDigest
	tagPayloadDigestAlgo
	tagAutoInstalled //  reservation (unimplemented)
	tagIdentity      //  reservation (unimplemented)
	tagModularityLabel
	tagPayloadDigestAlt
	tagArchSuffix
)

// Stealing a trick from codegen to assert some values.
func _() {
	var x [1]struct{}
	// These are the ends of all the contiguous ranges.
	_ = x[tagVeritySignatureAlgo-(_tagSigBase+21)]
	_ = x[tagTriggerIndex-1069]
	_ = x[tagNVRA-1196]
	_ = x[tagTriggerScriptFlags-5027]
	_ = x[tagPayloadDigestAlt-5097]
}

// kind is the kind of data stored in a given Tag.
type kind uint32

// Tag data Types.
const (
	typeNull kind = iota
	typeChar
	typeInt8
	typeInt16
	typeInt32
	typeInt64
	typeString
	typeBin
	typeStringArray
	typeI18nString

	typeRegionTag = typeBin
	typeMin       = typeChar
	typeMax       = typeI18nString
)

func (t kind) len(ct int, data []byte) (l int) {
	switch t {
	case typeString:
		if ct != 1 {
			return -1
		}
		fallthrough
	case typeStringArray:
		fallthrough
	case typeI18nString:
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

func (t kind) alignment() int32 {
	switch t {
	case typeNull, typeChar, typeInt8, typeString, typeBin, typeStringArray, typeI18nString:
		return 1
	case typeInt16:
		return 2
	case typeInt32:
		return 4
	case typeInt64:
		return 8
	default:
	}
	panic("programmer error")
}

func (t kind) class() (c class) {
	switch t {
	case typeNull:
		c = classNull
	case typeChar, typeInt8, typeInt16, typeInt32, typeInt64:
		c = classNumeric
	case typeString, typeStringArray, typeI18nString:
		c = classString
	case typeBin:
		c = classBinary
	default:
		panic("programmer error")
	}
	return c
}

// class is the type class of a Type.
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
