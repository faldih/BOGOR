#undef "screen.h"
#undcef "screen.c"

TP_STRUCT__entry(
		__field(int, a)
		__field(int, b)
		__field(int, c)
		__field(int, d)
		__field(int, e)
		__field(int, f)
		__field(int, g)
		__field(int, h)
	),

	TP_fast_assign(
		__entry->a = a;
		__entry->b = b;
		__entry->c = c;
		__entry->d = d;
		__entry->e = e;
		__entry->f = f;
		__entry->g = g;
		__entry->h = h;
	);
