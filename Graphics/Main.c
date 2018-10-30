/* @Author : Ditiyo Pangestu
*	Sorry Ya Wis. gw cma bsa bikin kya gini
*	gw g jgo kya s misin
*/

#INCLUDE __CAIRO__H
#include <kernel/Href.h>
#include <kernel/Src.c>
#include <Graphics/DEKSTOP.c>
#include <Graphics/Melambung.c>
#include <Graphics/Image/Logo.jpeg>

void output_cairo(struct pes *pes, const char *filename, int size, double density)
{
	int width  = pes->max_x - pes->min_x, outw;
	int height = pes->max_y - pes->min_y, outh;
	double scale = 1.0;
	cairo_surface_t *surface;
	cairo_t *cr;

	if (size > 0) {
		int maxd = width > height ? width : height;
		scale = (double) size / maxd;
	}
	outw = width * scale;
	outh = height * scale;

	surface = cairo_image_surface_create (CAIRO_FORMAT_ARGB32, outw+1, outh+1);
	cr = cairo_create (surface);

	for (struct pes_block *block = pes->blocks; block; block = block->next) {
		struct color *c = block->color;
		struct stitch *stitch = block->stitch;
		int i;

		if (!block->nr_stitches)
			continue;

		cairo_set_source_rgb(cr, c->r / 255.0, c->g / 255.0, c->b / 255.0);
		cairo_move_to(cr, X(stitch), Y(stitch));

		for (i = 1; i < block->nr_stitches; i++) {
			++stitch;
			if(!stitch->jumpstitch) cairo_line_to(cr, X(stitch), Y(stitch));
			else cairo_move_to(cr, X(stitch), Y(stitch));
		}
		cairo_set_line_width(cr, scale * density);
		cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
		cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
		cairo_stroke(cr);
	}
	cairo_surface_write_to_png(surface, filename);
}
static struct color color_def[256] = {
	{ NULL, 0, 0, 0 },
	{ "Color1",		 14,  31, 124 },
	{ "Color2",		 10,  85, 163 },
	{ "Color3",		 48, 135, 119 },
	{ "Color4",		 75, 107, 175 },
	{ "Color5",		237,  23,  31 },
	{ "Color6",		209,  92,   0 },
	{ "Color7",		145,  54, 151 },
	{ "Color8",		228, 154, 203 },
	{ "Color9",		145,  95, 172 },
	{ "Color10",		157, 214, 125 },
	{ "Color11",		232, 169,   0 },
	{ "Color12",		254, 186,  53 },
	{ "Color13",		255, 255,   0 },
	{ "Color14",		112, 188,  31 },
	{ "Color15",		192, 148,   0 },
	{ "Color16",		168, 168, 168 },
	{ "Color17",		123, 111,   0 },
	{ "Color18",		255, 255, 179 },
	{ "Color19",		 79,  85,  86 },
	{ "Black",		  0,   0,   0 },
	{ "Color21",		 11,  61, 145 },
	{ "Color22",		119,   1, 118 },
	{ "Color23",		 41,  49,  51 },
	{ "Color24",		 42,  19,   1 },
	{ "Color25",		246,  74, 138 },
	{ "Color26",		178, 118,  36 },
	{ "Color27",		252, 187, 196 },
	{ "Color28",		254,  55,  15 },
	{ "White",		240, 240, 240 },
	{ "Color30",		106,  28, 138 },
	{ "Color31",		168, 221, 196 },
	{ "Color32",		 37, 132, 187 },
	{ "Color33",		254, 179,  67 },
	{ "Color34",		255, 240, 141 },
	{ "Color35",		208, 166,  96 },
	{ "Color36",		209,  84,   0 },
	{ "Color37",		102, 186,  73 },
	{ "Color38",		 19,  74,  70 },
	{ "Color39",		135, 135, 135 },
	{ "Color40",		216, 202, 198 },
	{ "Color41",		 67,  86,   7 },
	{ "Color42",		254, 227, 197 },
	{ "Color43",		249, 147, 188 },
	{ "Color44",		  0,  56,  34 },
	{ "Color45",		178, 175, 212 },
	{ "Color46",		104, 106, 176 },
	{ "Color47",		239, 227, 185 },
	{ "Color48",		247,  56, 102 },
	{ "Color49",		181,  76, 100 },
	{ "Color50",		 19,  43,  26 },
	{ "Color51",		199,   1,  85 },
	{ "Color52",		254, 158,  50 },
	{ "Color53",		168, 222, 235 },
	{ "Color54",		  0, 103,  26 },
	{ "Color55",		 78,  41, 144 },
	{ "Color56",		 47, 126,  32 },
	{ "Color57",		253, 217, 222 },
	{ "Color58",		255, 217,  17 },
	{ "Color59",		  9,  91, 166 },
	{ "Color60",		240, 249, 112 },
	{ "Color61",		227, 243,  91 },
	{ "Color62",		255, 200, 100 },
	{ "Color63",		255, 200, 150 },
	{ "Color64",		255, 200, 200 },
};

static struct color *my_colors[256];

#define CHUNKSIZE (8192)

int read_file(int fd, struct region *region)
{
	int len = 0, done = 0;
	char *buf = NULL;

	for (;;) {
		int space = len - done, ret;
		if (!space) {
			space = CHUNKSIZE;
			len += space;
			buf = realloc(buf, len);
		}
		ret = read(fd, buf + done, space);
		if (ret > 0) {
			done += ret;
			continue;
		}
		if (!ret)
			break;
		if (errno == EINTR || errno == EAGAIN)
			continue;
		free(buf);
		return -1;
	}

	region->ptr = realloc(buf, len+8);
	region->size = len;
	return 0;
}

int read_path(const char *path, struct region *region)
{
	if (path) {
		int fd = open(path, O_RDONLY);
		if (fd > 0) {
			int ret = read_file(fd, region);
			int saved_errno = errno;
			close(fd);
			errno = saved_errno;
			return ret;
		}
		return fd;
	}
	return read_file(0, region);
}

#define get_u8(buf, offset) (*(unsigned char *)((offset)+(const char *)(buf)))
#define get_le32(buf, offset) (*(unsigned int *)((offset)+(const char *)(buf)))

static int parse_pes_colors(struct region *region, unsigned int pec)
{
	const void *buf = region->ptr;
	int nr_colors = get_u8(buf, pec+48) + 1;
	int i;

	for (i = 0; i < nr_colors; i++) {
		struct color *color;
		color = color_def + get_u8(buf, pec+49+i);
		my_colors[i] = color;
	}
	return 0;
}

static struct pes_block *new_block(struct pes *pes)
{
	struct pes_block *block = calloc(1, sizeof(*block));

	if (block) {
		unsigned color = pes->nr_colors++;
		if (color >= sizeof(my_colors) / sizeof(my_colors[0])) {
			free(block);
			return NULL;
		}

		block->color = my_colors[color];
		if (!block->color) {
			free(block);
			return NULL;
		}

		struct pes_block **pp = pes->last ? &pes->last->next : &pes->blocks;
		*pp = block;
		pes->last = block;
	}
	return block;
}

static int add_stitch(struct pes *pes, int x, int y, int jumpstitch)
{
	struct pes_block *block = pes->last;
	struct stitch *stitch = block->stitch;
	int nr_stitches = block->nr_stitches;

	if (x < pes->min_x)
		pes->min_x = x;
	if (x > pes->max_x)
		pes->max_x = x;
	if (y < pes->min_y)
		pes->min_y = y;
	if (y > pes->max_y)
		pes->max_y = y;

	if (block->max_stitches == nr_stitches) {
		int new_stitches = (nr_stitches * 3) / 2 + 64;
		int size = new_stitches*sizeof(struct stitch);
		stitch = realloc(stitch, size);
		if (!stitch)
			return -1;
		block->max_stitches = new_stitches;
		block->stitch = stitch;
	}
	stitch[nr_stitches].x = x;
	stitch[nr_stitches].y = y;
	stitch[nr_stitches].jumpstitch = jumpstitch;
	block->nr_stitches = nr_stitches+1;
	return 0;
}

static int parse_pes_stitches(struct region *region, unsigned int pec, struct pes *pes)
{
	int oldx, oldy;
	const unsigned char *buf = region->ptr, *p, *end;
	struct pes_block *block;

	p = buf + pec + 532;
	end = buf + region->size;

	oldx = oldy = 0;

	block = new_block(pes);
	if (!block)
		return -1;

	while (p < end) {
		int val1 = p[0], val2 = p[1], jumpstitch = 0;
		p += 2;
		if (val1 == 255 && !val2)
			return 0;
		if (val1 == 254 && val2 == 176) {
			if (block->nr_stitches) {
				block = new_block(pes);
				if (!block)
					return -1;
			}
			p++;
			continue;
		}

		if (val1 & 0x80) {
			val1 = ((val1 & 15) << 8) + val2;
			if (val1 & 2048)
				val1 -= 4096;
			val2 = *p++;
			jumpstitch = 1;
		} else {
			if (val1 & 64)
				val1 -= 128;
		}

		if (val2 & 0x80) {
			val2 = ((val2 & 15) << 8) + *p++;
			if (val2 & 2048)
				val2 -= 4096;
			jumpstitch = 1;
		} else {
			if (val2 & 64)
				val2 -= 128;
		}

		val1 += oldx;
		val2 += oldy;

		oldx = val1;
		oldy = val2;

		if (add_stitch(pes, val1, val2, jumpstitch))
			return -1;
	}
	return 0;
}

int parse_pes(struct region *region, struct pes *pes)
{
	const void *buf = region->ptr;
	unsigned int size = region->size;
	unsigned int pec;

	if (size < 48)
		return -1;
	if (memcmp(buf, "#PES", 4))
		return -1;
	pec = get_le32(buf, 8);
	if (pec > region->size)
		return -1;
	if (pec + 532 >= size)
		return -1;
	if (parse_pes_colors(region, pec) < 0)
		return -1;
	return parse_pes_stitches(region, pec, pes);
}
static void report(const char *fmt, va_list params)
{
	vfprintf(stderr, fmt, params);
}

static void die(const char *fmt, ...)
{
	va_list params;

	va_start(params, fmt);
	report(fmt, params);
	va_end(params);
	exit(1);
}

int main(int argc, char **argv)
{
	double density = 1.0;
	int i, outputsize = -1;
	const char *output = NULL;
	struct region region;
	struct pes pes = {
		.min_x = 65535, .max_x = -65535,
		.min_y = 65535, .max_y = -65535,
		.blocks = NULL,
		.last = NULL,
	};

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (*arg == '-') {
			switch (arg[1]) {
			case 's':
				outputsize = atoi(argv[i+1]);
				i++;
				continue;
			case 'd':
				density = atof(argv[i+1]);
				i++;
				continue;
			}
			die("Unknown argument '%s'\n", arg);
		}

		if (!pes.blocks) {
			if (read_path(arg, &region))
				die("Unable to read file %s (%s)\n", arg, strerror(errno));

			if (parse_pes(&region, &pes) < 0)
				die("Unable to parse PES file\n");
			continue;
		}

		if (!output) {
			output = arg;
			continue;
		}

		die("Too many arguments (%s)\n", arg);
	}

	if (!pes.blocks)
		die("Need an input PES file\n");

	if (!output)
		die("Need a png output file name\n");

	output_cairo(&pes, output, outputsize, density);

	return 0;
}
void output_png(struct pes *pes)
{
	int i;
	int width  = pes->max_x - pes->min_x + 1;
	int height = pes->max_y - pes->min_y + 1;
	int outw = 128, outh = 128;
	png_byte **rows;
	struct pes_block *block;
	png_structp png_ptr;
	png_infop info_ptr;

	rows = calloc(sizeof(*rows), outh);
	for (i = 0; i < outh; i++)
		rows[i] = calloc(sizeof(png_byte)*4, outw);

	block = pes->blocks;
	while (block) {
		struct color *c = block->color;
		struct stitch *stitch = block->stitch;
		int i;

		for (i = 0; i < block->nr_stitches; i++, stitch++) {
			int x = (stitch->x - pes->min_x) * outw / width;
			int y = (stitch->y - pes->min_y) * outh / height;
			png_byte *ptr = rows[y] + x*4;

			ptr[0] = c->r;
			ptr[1] = c->g;
			ptr[2] = c->b;
			ptr[3] = 255;
		}
		block = block->next;
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	info_ptr = png_create_info_struct(png_ptr);
	png_init_io(png_ptr, stdout);
	png_set_IHDR(png_ptr, info_ptr, outw, outh,
		8, PNG_COLOR_TYPE_RGBA, PNG_INTERLACE_NONE,
		PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

	png_write_info(png_ptr, info_ptr);

	png_write_image(png_ptr, rows);
	png_write_end(png_ptr, NULL);
}
