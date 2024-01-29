module {};

def intersect($v):
	arrays // error("intersect/1 takes arrays as '.'") |
	$v - ($v - .)
;
