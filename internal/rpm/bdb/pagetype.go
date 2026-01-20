package bdb

//go:generate go run golang.org/x/tools/cmd/stringer@latest -linecomment -type=PageType,HashPageType

// PageType is the type of a page.
//
// This is always at offset 25 (0x19) of a page.
type PageType byte

// Page Types
const (
	PageTypeInvalid PageType = iota // P_INVALID
	// Deprecated: Deprecated in version 3.1.
	PageTypeDuplicate     // P_DUPLICATE
	PageTypeHashUnsorted  // P_HASH_UNSORTED
	PageTypeBtreeInternal // P_IBTREE
	PageTypeRecnoInternal // P_IRECNO
	PageTypeBtreeLeaf     // P_LBTREE
	PageTypeRecnoLeaf     // P_LRECNO
	PageTypeOverflow      // P_OVERFLOW
	PageTypeHashMeta      // P_HASHMETA
	PageTypeBtreeMeta     // P_BTREEMETA
	PageTypeQamMeta       // P_QAMMETA
	PageTypeQamData       // P_QAMDATA
	PageTypeDupLeaf       // P_LDUP
	PageTypeHash          // P_HASH
	PageTypeHeapMeta      // P_HEAPMETA
	PageTypeHeap          // P_HEAP
	PageTypeHeapInternal  // P_IHEAP
)

// HashPageType is the type of an internal hash page.
type HashPageType byte

// Hash Page Types
const (
	HashPageTypeInvalid HashPageType = iota
	HashPageTypeKeyData
	HashPageTypeDuplicate
	HashPageTypeOffpage
	HashPageTypeOffDup
	HashPageTypeBlob
)
