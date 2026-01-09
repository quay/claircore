#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Some magic builtins and compiler wrangling:
#define HOST(s) __attribute((import_module("claircore_matcher_1"), import_name(s)))
#define STRING_GETTER(t, r, f) HOST(#r "_get_" #f) ptrdiff_t r##_get_##f(t, char*, size_t)
#define REF_GETTER(t, e, r, f) HOST(#r "_get_" #f) e r##_get_##f(t)
#define REF_VALID(t, r) HOST(#r "_valid") bool r##_valid(t)
#define EXPORT(s) __attribute__((export_name(s)))
size_t __builtin_wasm_memory_size(int);
size_t __builtin_wasm_memory_grow(int, size_t);
extern char __heap_base[];

// Arena allocator.
//
// Thanks for the inspiration, skeeto:
// - https://nullprogram.com/blog/2023/09/27/
// - https://nullprogram.com/blog/2025/04/19/
//
// This is all extremely single-threaded.

typedef struct {
    char *beg;
    char *end;
} Arena;

//static bool init = false;

Arena getarena(void)
{
//	if(!init){
//		// Allocate our heap.
//		__builtin_wasm_memory_grow(0, __builtin_wasm_memory_size(0));
//		init = true;
//	}
    Arena a = {0};
    a.beg = __heap_base;
    a.end = (char *)(__builtin_wasm_memory_size(0) << 16);
    return a;
}

static void *alloc(Arena *a, ptrdiff_t count, ptrdiff_t size, ptrdiff_t align)
{
    ptrdiff_t pad = (ptrdiff_t)-(size_t)a->beg & (align - 1);
    char *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, (size_t)(size*count));
}

typedef struct {
    char *s;
	size_t len;
    ptrdiff_t cap;
} Str;

static Str allocStr(Arena *a, ptrdiff_t max)
{
	Str s = {0};
	char *p = alloc(a, 1, max, 4);
	s.s = p;
	s.cap = max;
	return s;
}

// Host interface:

typedef __externref_t DetectorRef;
typedef __externref_t DistributionRef;
typedef __externref_t IndexrecordRef;
typedef __externref_t PackageRef;
typedef __externref_t RangeRef;
typedef __externref_t RepositoryRef;
typedef __externref_t VulnerabilityRef;

typedef uint32_t MatchConstraints;
typedef enum MatchConstraintFlags{
	PackageSourceName = 1<<0,
	PackageName = 1<<1,
	PackageModule = 1<<2,
	DistributionDID = 1<<3,
	DistributionName = 1<<4,
	DistributionVersion = 1<<5,
	DistributionVersionCodeName = 1<<6,
	DistributionVersionID = 1<<7,
	DistributionArch = 1<<8,
	DistributionCPE = 1<<9,
	DistributionPrettyName = 1<<10,
	RepositoryName = 1<<11,
	RepositoryKey = 1<<12,
	HasFixedInVersion = 1<<13,
} MatchConstraintFlags;

REF_VALID(DetectorRef, detector);
STRING_GETTER(DetectorRef, detector, kind);
STRING_GETTER(DetectorRef, detector, name);
STRING_GETTER(DetectorRef, detector, version);

REF_VALID(DistributionRef, distribution);
STRING_GETTER(DistributionRef, distribution, architecture);
STRING_GETTER(DistributionRef, distribution, cpe);
STRING_GETTER(DistributionRef, distribution, did);
STRING_GETTER(DistributionRef, distribution, name);
STRING_GETTER(DistributionRef, distribution, prettyname);
STRING_GETTER(DistributionRef, distribution, version);
STRING_GETTER(DistributionRef, distribution, versioncodename);
STRING_GETTER(DistributionRef, distribution, versionid);

// Always valid.
REF_GETTER(IndexrecordRef, DistributionRef, indexrecord, distribution);
REF_GETTER(IndexrecordRef, PackageRef, indexrecord, package);
REF_GETTER(IndexrecordRef, RepositoryRef, indexrecord, repository);

REF_VALID(PackageRef, package);
STRING_GETTER(PackageRef, package, architecture);
STRING_GETTER(PackageRef, package, cpe);
REF_GETTER(PackageRef, DetectorRef, package, detector);
STRING_GETTER(PackageRef, package, filepath);
STRING_GETTER(PackageRef, package, kind);
STRING_GETTER(PackageRef, package, module);
STRING_GETTER(PackageRef, package, name);
STRING_GETTER(PackageRef, package, packagedb);
STRING_GETTER(PackageRef, package, repositoryhint);
REF_GETTER(PackageRef, PackageRef, package, source);
STRING_GETTER(PackageRef, package, version);

REF_VALID(RangeRef, range);

REF_VALID(RepositoryRef, repository);
STRING_GETTER(RepositoryRef, repository, cpe);
STRING_GETTER(RepositoryRef, repository, key);
STRING_GETTER(RepositoryRef, repository, name);
STRING_GETTER(RepositoryRef, repository, uri);

// Always valid.
STRING_GETTER(VulnerabilityRef, vulnerability, description);
REF_GETTER(VulnerabilityRef, DistributionRef, vulnerability, distribution);
STRING_GETTER(VulnerabilityRef, vulnerability, fixedinversion);
STRING_GETTER(VulnerabilityRef, vulnerability, issued);
STRING_GETTER(VulnerabilityRef, vulnerability, links);
STRING_GETTER(VulnerabilityRef, vulnerability, name);
REF_GETTER(VulnerabilityRef, PackageRef, vulnerability, package);
REF_GETTER(VulnerabilityRef, RangeRef, vulnerability, range);
REF_GETTER(VulnerabilityRef, RepositoryRef, vulnerability, repository);
STRING_GETTER(VulnerabilityRef, vulnerability, severity);
STRING_GETTER(VulnerabilityRef, vulnerability, updater);

// Implementation:

const MatchConstraints query = (PackageName|HasFixedInVersion);

EXPORT("filter")
bool filter(IndexrecordRef r) {
	Arena a = getarena();

	PackageRef p = indexrecord_get_package(r);
	if(!package_valid(p))
		return false;

	Str name = allocStr(&a, 1024);
	ptrdiff_t len = package_get_name(p, name.s, name.cap);
	name.len = len;

	return name.len > 0;
}

EXPORT("vulnerable")
bool vulnerable(IndexrecordRef r, VulnerabilityRef v) {
	return false;
}
