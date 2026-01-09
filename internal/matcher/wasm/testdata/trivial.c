#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Some magic builtins and compiler wrangling:
#define HOST(s) __attribute((import_module("claircore_matcher_1"), import_name(s)))
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

static bool init = false;

Arena getarena(void)
{
	if(!init){
		// Allocate our heap.
		__builtin_wasm_memory_grow(0, __builtin_wasm_memory_size(0));
		init = true;
	}
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

typedef __externref_t DistributionRef;
typedef __externref_t IndexrecordRef;
typedef __externref_t PackageRef;
typedef __externref_t RepositoryRef;
typedef __externref_t VulnerabilityRef;
typedef int32_t MatchConstraints;

HOST("indexrecord_get_package")
PackageRef indexrecord_get_package(IndexrecordRef);
HOST("indexrecord_get_distribution")
DistributionRef indexrecord_get_distribution(IndexrecordRef);
HOST("indexrecord_get_repository")
RepositoryRef indexrecord_get_repository(IndexrecordRef);

HOST("package_get_name")
ptrdiff_t package_get_name(PackageRef, char*, size_t);

// Implementation:

EXPORT("query")
MatchConstraints query() {
	return 0;
}

EXPORT("filter")
bool filter(IndexrecordRef r) {
	Arena a = getarena();

	PackageRef p = indexrecord_get_package(r);
	Str name = allocStr(&a, 1024);
	ptrdiff_t len = package_get_name(p, name.s, name.cap);
	name.len = len;

	return name.len > 0;
}

EXPORT("vulnerable")
bool vulnerable(IndexrecordRef r, VulnerabilityRef v) {
	return false;
}
