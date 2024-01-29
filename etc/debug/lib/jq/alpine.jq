module {};

import "claircore" as lib;

def find_advisories($v):
	.packages[] |
	.pkg |
	.name as $name |
	.secfixes |
	to_entries |
	.[] |
	.key as $version |
	.value|
	lib::intersect($v) |
	select(any) |
	[($name), ($version), (.)]
;
