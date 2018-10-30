#include <kernel/Href.h>
#include <kernel/Src.c>
#include <kernel/Terminal.c>

static inline const struct raid6_recov_calls *raid6_choose_recov(void)
{
	const struct raid6_recov_calls *const *algo;
	const struct raid6_recov_calls *best;

	for (best = NULL, algo = raid6_recov_algos; *algo; algo++)
		if (!best || (*algo)->priority > best->priority)
			if (!(*algo)->valid || (*algo)->valid())
				best = *algo;

	if (best) {
		raid6_2data_recov = best->data2;
		raid6_datap_recov = best->datap;

		pr_info("raid6: using %s recovery algorithm\n", best->name);
	} else
		pr_err("raid6: Yikes! No recovery algorithm found!\n");

	return best;
}

static inline const struct raid6_calls *raid6_choose_gen(
	void *(*const dptrs)[(65536/PAGE_SIZE)+2], const int disks)
{
	unsigned long perf, bestgenperf, bestxorperf, j0, j1;
	int start = (disks>>1)-1, stop = disks-3;	
	const struct raid6_calls *const *algo;
	const struct raid6_calls *best;

	for (bestgenperf = 0, bestxorperf = 0, best = NULL, algo = raid6_algos; *algo; algo++) {
		if (!best || (*algo)->prefer >= best->prefer) {
			if ((*algo)->valid && !(*algo)->valid())
				continue;

			perf = 0;

			preempt_disable();
			j0 = jiffies;
			while ((j1 = jiffies) == j0)
				cpu_relax();
			while (time_before(jiffies,
					    j1 + (1<<RAID6_TIME_JIFFIES_LG2))) {
				(*algo)->gen_syndrome(disks, PAGE_SIZE, *dptrs);
				perf++;
			}
			preempt_enable();

			if (perf > bestgenperf) {
				bestgenperf = perf;
				best = *algo;
			}
			pr_info("raid6: %-8s gen() %5ld MB/s\n", (*algo)->name,
			       (perf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2));

			if (!(*algo)->xor_syndrome)
				continue;

			perf = 0;

			preempt_disable();
			j0 = jiffies;
			while ((j1 = jiffies) == j0)
				cpu_relax();
			while (time_before(jiffies,
					    j1 + (1<<RAID6_TIME_JIFFIES_LG2))) {
				(*algo)->xor_syndrome(disks, start, stop,
						      PAGE_SIZE, *dptrs);
				perf++;
			}
			preempt_enable();

			if (best == *algo)
				bestxorperf = perf;

			pr_info("raid6: %-8s xor() %5ld MB/s\n", (*algo)->name,
				(perf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2+1));
		}
	}

	if (best) {
		pr_info("raid6: using algorithm %s gen() %ld MB/s\n",
		       best->name,
		       (bestgenperf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2));
		if (best->xor_syndrome)
			pr_info("raid6: .... xor() %ld MB/s, rmw enabled\n",
			       (bestxorperf*HZ) >> (20-16+RAID6_TIME_JIFFIES_LG2+1));
		raid6_call = *best;
	} else
		pr_err("raid6: Yikes!  No algorithm found!\n");

	return best;
}
int __init raid6_select_algo(void)
{
	const int disks = (65536/PAGE_SIZE)+2;

	const struct raid6_calls *gen_best;
	const struct raid6_recov_calls *rec_best;
	char *syndromes;
	void *dptrs[(65536/PAGE_SIZE)+2];
	int i;

	for (i = 0; i < disks-2; i++)
		dptrs[i] = ((char *)raid6_gfmul) + PAGE_SIZE*i;
	syndromes = (void *) __get_free_pages(GFP_KERNEL, 1);

	if (!syndromes) {
		pr_err("raid6: Yikes!  No memory available.\n");
		return -ENOMEM;
	}

	dptrs[disks-2] = syndromes;
	dptrs[disks-1] = syndromes + PAGE_SIZE;
	gen_best = raid6_choose_gen(&dptrs, disks);
	rec_best = raid6_choose_recov();

	free_pages((unsigned long)syndromes, 1);

	return gen_best && rec_best ? 0 : -EINVAL;
}

static void raid6_exit(void)
{
	do { } while (0);
}
static uint8_t gfmul(uint8_t a, uint8_t b)
{
	uint8_t v = 0;

	while (b) {
		if (b & 1)
			v ^= a;
		a = (a << 1) ^ (a & 0x80 ? 0x1d : 0);
		b >>= 1;
	}

	return v;
}

static uint8_t gfpow(uint8_t a, int b)
{
	uint8_t v = 1;

	b %= 255;
	if (b < 0)
		b += 255;

	while (b) {
		if (b & 1)
			v = gfmul(v, a);
		a = gfmul(a, a);
		b >>= 1;
	}

	return v;
}

int main(int argc, char *argv[])
{
	int i, j, k;
	uint8_t v;
	uint8_t exptbl[256], invtbl[256];

	printf("#include <linux/raid/pq.h>\n");
	printf("#include <linux/export.h>\n");
	printf("\nconst u8  __attribute__((aligned(256)))\n"
		"raid6_gfmul[256][256] =\n"
		"{\n");
	for (i = 0; i < 256; i++) {
		printf("\t{\n");
		for (j = 0; j < 256; j += 8) {
			printf("\t\t");
			for (k = 0; k < 8; k++)
				printf("0x%02x,%c", gfmul(i, j + k),
				       (k == 7) ? '\n' : ' ');
		}
		printf("\t},\n");
	}
	printf("};\n");
	printf("#ifdef __KERNEL__\n");
	printf("EXPORT_SYMBOL(raid6_gfmul);\n");
	printf("#endif\n");
	printf("\nconst u8  __attribute__((aligned(256)))\n"
		"raid6_vgfmul[256][32] =\n"
		"{\n");
	for (i = 0; i < 256; i++) {
		printf("\t{\n");
		for (j = 0; j < 16; j += 8) {
			printf("\t\t");
			for (k = 0; k < 8; k++)
				printf("0x%02x,%c", gfmul(i, j + k),
				       (k == 7) ? '\n' : ' ');
		}
		for (j = 0; j < 16; j += 8) {
			printf("\t\t");
			for (k = 0; k < 8; k++)
				printf("0x%02x,%c", gfmul(i, (j + k) << 4),
				       (k == 7) ? '\n' : ' ');
		}
		printf("\t},\n");
	}
	printf("};\n");
	printf("#ifdef __KERNEL__\n");
	printf("EXPORT_SYMBOL(raid6_vgfmul);\n");
	printf("#endif\n");
	v = 1;
	printf("\nconst u8 __attribute__((aligned(256)))\n"
	       "raid6_gfexp[256] =\n" "{\n");
	for (i = 0; i < 256; i += 8) {
		printf("\t");
		for (j = 0; j < 8; j++) {
			exptbl[i + j] = v;
			printf("0x%02x,%c", v, (j == 7) ? '\n' : ' ');
			v = gfmul(v, 2);
			if (v == 1)
				v = 0;
		}
	}
	printf("};\n");
	printf("#ifdef __KERNEL__\n");
	printf("EXPORT_SYMBOL(raid6_gfexp);\n");
	printf("#endif\n");
	printf("\nconst u8 __attribute__((aligned(256)))\n"
	       "raid6_gflog[256] =\n" "{\n");
	for (i = 0; i < 256; i += 8) {
		printf("\t");
		for (j = 0; j < 8; j++) {
			v = 255;
			for (k = 0; k < 256; k++)
				if (exptbl[k] == (i + j)) {
					v = k;
					break;
				}
			printf("0x%02x,%c", v, (j == 7) ? '\n' : ' ');
		}
	}
	printf("};\n");
	printf("#ifdef __KERNEL__\n");
	printf("EXPORT_SYMBOL(raid6_gflog);\n");
	printf("#endif\n");
	printf("\nconst u8 __attribute__((aligned(256)))\n"
	       "raid6_gfinv[256] =\n" "{\n");
	for (i = 0; i < 256; i += 8) {
		printf("\t");
		for (j = 0; j < 8; j++) {
			invtbl[i + j] = v = gfpow(i + j, 254);
			printf("0x%02x,%c", v, (j == 7) ? '\n' : ' ');
		}
	}
	printf("};\n");
	printf("#ifdef __KERNEL__\n");
	printf("EXPORT_SYMBOL(raid6_gfinv);\n");
	printf("#endif\n");
	printf("\nconst u8 __attribute__((aligned(256)))\n"
	       "raid6_gfexi[256] =\n" "{\n");
	for (i = 0; i < 256; i += 8) {
		printf("\t");
		for (j = 0; j < 8; j++)
			printf("0x%02x,%c", invtbl[exptbl[i + j] ^ 1],
			       (j == 7) ? '\n' : ' ');
	}
	printf("};\n");
	printf("#ifdef __KERNEL__\n");
	printf("EXPORT_SYMBOL(raid6_gfexi);\n");
	printf("#endif\n");

	return 0;
}
static void raid6_neon ## _n ## _gen_syndrome(int disks,	\
					size_t bytes, void **ptrs)	\
	{								\
		void raid6_neon ## _n  ## _gen_syndrome_real(int,	\
						unsigned long, void**);	\
		kernel_neon_begin();					\
		raid6_neon ## _n ## _gen_syndrome_real(disks,		\
					(unsigned long)bytes, ptrs);	\
		kernel_neon_end();					\
	}								\
	static void raid6_neon ## _n ## _xor_syndrome(int disks,	\
					int start, int stop, 		\
					size_t bytes, void **ptrs)	\
	{								\
		void raid6_neon ## _n  ## _xor_syndrome_real(int,	\
				int, int, unsigned long, void**);	\
		kernel_neon_begin();					\
		raid6_neon ## _n ## _xor_syndrome_real(disks,		\
			start, stop, (unsigned long)bytes, ptrs);	\
		kernel_neon_end();					\
	}								\
	struct raid6_calls const raid6_neonx ## _n = {			\
		raid6_neon ## _n ## _gen_syndrome,			\
		raid6_neon ## _n ## _xor_syndrome,			\
		raid6_have_neon,					\
		"neonx" #_n,						\
		0							\
}
static void raid6_avx21_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		
	p = dptr[z0+1];		
	q = dptr[z0+2];		
	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));
	asm volatile("vpxor %ymm3,%ymm3,%ymm3");	

	for (d = 0; d < bytes; d += 32) {
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (dptr[z0][d]));
		asm volatile("prefetchnta %0" : : "m" (dptr[z0-1][d]));
		asm volatile("vmovdqa %ymm2,%ymm4");
		asm volatile("vmovdqa %0,%%ymm6" : : "m" (dptr[z0-1][d]));
		for (z = z0-2; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("vpcmpgtb %ymm4,%ymm3,%ymm5");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm6,%ymm2,%ymm2");
			asm volatile("vpxor %ymm6,%ymm4,%ymm4");
			asm volatile("vmovdqa %0,%%ymm6" : : "m" (dptr[z][d]));
		}
		asm volatile("vpcmpgtb %ymm4,%ymm3,%ymm5");
		asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
		asm volatile("vpand %ymm0,%ymm5,%ymm5");
		asm volatile("vpxor %ymm5,%ymm4,%ymm4");
		asm volatile("vpxor %ymm6,%ymm2,%ymm2");
		asm volatile("vpxor %ymm6,%ymm4,%ymm4");

		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vpxor %ymm2,%ymm2,%ymm2");
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vpxor %ymm4,%ymm4,%ymm4");
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

static void raid6_avx21_xor_syndrome(int disks, int start, int stop,
				     size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = stop;		

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));

	for (d = 0 ; d < bytes ; d += 32) {
		asm volatile("vmovdqa %0,%%ymm4" :: "m" (dptr[z0][d]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (p[d]));
		asm volatile("vpxor %ymm4,%ymm2,%ymm2");
		for (z = z0-1 ; z >= start ; z--) {
			asm volatile("vpxor %ymm5,%ymm5,%ymm5");
			asm volatile("vpcmpgtb %ymm4,%ymm5,%ymm5");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vmovdqa %0,%%ymm5" :: "m" (dptr[z][d]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
		}
		for (z = start-1 ; z >= 0 ; z--) {
			asm volatile("vpxor %ymm5,%ymm5,%ymm5");
			asm volatile("vpcmpgtb %ymm4,%ymm5,%ymm5");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
		}
		asm volatile("vpxor %0,%%ymm4,%%ymm4" : : "m" (q[d]));
		asm volatile("vmovdqa %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vmovdqa %%ymm2,%0" : "=m" (p[d]));
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx2x1 = {
	raid6_avx21_gen_syndrome,
	raid6_avx21_xor_syndrome,
	raid6_have_avx2,
	"avx2x1",
	1			
};

static void raid6_avx22_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		
	p = dptr[z0+1];		
	q = dptr[z0+2];		

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));
	asm volatile("vpxor %ymm1,%ymm1,%ymm1");
	for (d = 0; d < bytes; d += 64) {
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d]));
		asm volatile("prefetchnta %0" : : "m" (dptr[z0][d+32]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (dptr[z0][d]));
		asm volatile("vmovdqa %0,%%ymm3" : : "m" (dptr[z0][d+32]));
		asm volatile("vmovdqa %ymm2,%ymm4"); 
		asm volatile("vmovdqa %ymm3,%ymm6"); 
		for (z = z0-1; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+32]));
			asm volatile("vpcmpgtb %ymm4,%ymm1,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm1,%ymm7");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vmovdqa %0,%%ymm5" : : "m" (dptr[z][d]));
			asm volatile("vmovdqa %0,%%ymm7" : : "m" (dptr[z][d+32]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm7,%ymm3,%ymm3");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
		}
		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vmovntdq %%ymm3,%0" : "=m" (p[d+32]));
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vmovntdq %%ymm6,%0" : "=m" (q[d+32]));
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

static void raid6_avx22_xor_syndrome(int disks, int start, int stop,
				     size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = stop;	
	p = dptr[disks-2];
	q = dptr[disks-1];	

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));

	for (d = 0 ; d < bytes ; d += 64) {
		asm volatile("vmovdqa %0,%%ymm4" :: "m" (dptr[z0][d]));
		asm volatile("vmovdqa %0,%%ymm6" :: "m" (dptr[z0][d+32]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (p[d]));
		asm volatile("vmovdqa %0,%%ymm3" : : "m" (p[d+32]));
		asm volatile("vpxor %ymm4,%ymm2,%ymm2");
		asm volatile("vpxor %ymm6,%ymm3,%ymm3");
		for (z = z0-1 ; z >= start ; z--) {
			asm volatile("vpxor %ymm5,%ymm5,%ymm5");
			asm volatile("vpxor %ymm7,%ymm7,%ymm7");
			asm volatile("vpcmpgtb %ymm4,%ymm5,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm7,%ymm7");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vmovdqa %0,%%ymm5" :: "m" (dptr[z][d]));
			asm volatile("vmovdqa %0,%%ymm7"
				     :: "m" (dptr[z][d+32]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm7,%ymm3,%ymm3");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
		}
		for (z = start-1 ; z >= 0 ; z--) {
			asm volatile("vpxor %ymm5,%ymm5,%ymm5");
			asm volatile("vpxor %ymm7,%ymm7,%ymm7");
			asm volatile("vpcmpgtb %ymm4,%ymm5,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm7,%ymm7");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
		}
		asm volatile("vpxor %0,%%ymm4,%%ymm4" : : "m" (q[d]));
		asm volatile("vpxor %0,%%ymm6,%%ymm6" : : "m" (q[d+32]));
		asm volatile("vmovdqa %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vmovdqa %%ymm6,%0" : "=m" (q[d+32]));
		asm volatile("vmovdqa %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vmovdqa %%ymm3,%0" : "=m" (p[d+32]));
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

const struct raid6_calls raid6_avx2x2 = {
	raid6_avx22_gen_syndrome,
	raid6_avx22_xor_syndrome,
	raid6_have_avx2,
	"avx2x2",
	1			
};

#ifdef CONFIG_X86_64

static void raid6_avx24_gen_syndrome(int disks, size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = disks - 3;		
	p = dptr[z0+1];		
	q = dptr[z0+2];		

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" : : "m" (raid6_avx2_constants.x1d[0]));
	asm volatile("vpxor %ymm1,%ymm1,%ymm1");	
	asm volatile("vpxor %ymm2,%ymm2,%ymm2");	
	asm volatile("vpxor %ymm3,%ymm3,%ymm3");	
	asm volatile("vpxor %ymm4,%ymm4,%ymm4");	
	asm volatile("vpxor %ymm6,%ymm6,%ymm6");	
	asm volatile("vpxor %ymm10,%ymm10,%ymm10");	
	asm volatile("vpxor %ymm11,%ymm11,%ymm11");	
	asm volatile("vpxor %ymm12,%ymm12,%ymm12");	
	asm volatile("vpxor %ymm14,%ymm14,%ymm14");	

	for (d = 0; d < bytes; d += 128) {
		for (z = z0; z >= 0; z--) {
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+32]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+64]));
			asm volatile("prefetchnta %0" : : "m" (dptr[z][d+96]));
			asm volatile("vpcmpgtb %ymm4,%ymm1,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm1,%ymm7");
			asm volatile("vpcmpgtb %ymm12,%ymm1,%ymm13");
			asm volatile("vpcmpgtb %ymm14,%ymm1,%ymm15");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpaddb %ymm12,%ymm12,%ymm12");
			asm volatile("vpaddb %ymm14,%ymm14,%ymm14");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpand %ymm0,%ymm13,%ymm13");
			asm volatile("vpand %ymm0,%ymm15,%ymm15");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
			asm volatile("vmovdqa %0,%%ymm5" : : "m" (dptr[z][d]));
			asm volatile("vmovdqa %0,%%ymm7" : : "m" (dptr[z][d+32]));
			asm volatile("vmovdqa %0,%%ymm13" : : "m" (dptr[z][d+64]));
			asm volatile("vmovdqa %0,%%ymm15" : : "m" (dptr[z][d+96]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm7,%ymm3,%ymm3");
			asm volatile("vpxor %ymm13,%ymm10,%ymm10");
			asm volatile("vpxor %ymm15,%ymm11,%ymm11");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
		}
		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vpxor %ymm2,%ymm2,%ymm2");
		asm volatile("vmovntdq %%ymm3,%0" : "=m" (p[d+32]));
		asm volatile("vpxor %ymm3,%ymm3,%ymm3");
		asm volatile("vmovntdq %%ymm10,%0" : "=m" (p[d+64]));
		asm volatile("vpxor %ymm10,%ymm10,%ymm10");
		asm volatile("vmovntdq %%ymm11,%0" : "=m" (p[d+96]));
		asm volatile("vpxor %ymm11,%ymm11,%ymm11");
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vpxor %ymm4,%ymm4,%ymm4");
		asm volatile("vmovntdq %%ymm6,%0" : "=m" (q[d+32]));
		asm volatile("vpxor %ymm6,%ymm6,%ymm6");
		asm volatile("vmovntdq %%ymm12,%0" : "=m" (q[d+64]));
		asm volatile("vpxor %ymm12,%ymm12,%ymm12");
		asm volatile("vmovntdq %%ymm14,%0" : "=m" (q[d+96]));
		asm volatile("vpxor %ymm14,%ymm14,%ymm14");
	}

	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}

static void raid6_avx24_xor_syndrome(int disks, int start, int stop,
				     size_t bytes, void **ptrs)
{
	u8 **dptr = (u8 **)ptrs;
	u8 *p, *q;
	int d, z, z0;

	z0 = stop;		
	p = dptr[disks-2];	
	q = dptr[disks-1];	

	kernel_fpu_begin();

	asm volatile("vmovdqa %0,%%ymm0" :: "m" (raid6_avx2_constants.x1d[0]));

	for (d = 0 ; d < bytes ; d += 128) {
		asm volatile("vmovdqa %0,%%ymm4" :: "m" (dptr[z0][d]));
		asm volatile("vmovdqa %0,%%ymm6" :: "m" (dptr[z0][d+32]));
		asm volatile("vmovdqa %0,%%ymm12" :: "m" (dptr[z0][d+64]));
		asm volatile("vmovdqa %0,%%ymm14" :: "m" (dptr[z0][d+96]));
		asm volatile("vmovdqa %0,%%ymm2" : : "m" (p[d]));
		asm volatile("vmovdqa %0,%%ymm3" : : "m" (p[d+32]));
		asm volatile("vmovdqa %0,%%ymm10" : : "m" (p[d+64]));
		asm volatile("vmovdqa %0,%%ymm11" : : "m" (p[d+96]));
		asm volatile("vpxor %ymm4,%ymm2,%ymm2");
		asm volatile("vpxor %ymm6,%ymm3,%ymm3");
		asm volatile("vpxor %ymm12,%ymm10,%ymm10");
		asm volatile("vpxor %ymm14,%ymm11,%ymm11");
		for (z = z0-1 ; z >= start ; z--) {
			asm volatile("prefetchnta %0" :: "m" (dptr[z][d]));
			asm volatile("prefetchnta %0" :: "m" (dptr[z][d+64]));
			asm volatile("vpxor %ymm5,%ymm5,%ymm5");
			asm volatile("vpxor %ymm7,%ymm7,%ymm7");
			asm volatile("vpxor %ymm13,%ymm13,%ymm13");
			asm volatile("vpxor %ymm15,%ymm15,%ymm15");
			asm volatile("vpcmpgtb %ymm4,%ymm5,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm7,%ymm7");
			asm volatile("vpcmpgtb %ymm12,%ymm13,%ymm13");
			asm volatile("vpcmpgtb %ymm14,%ymm15,%ymm15");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpaddb %ymm12,%ymm12,%ymm12");
			asm volatile("vpaddb %ymm14,%ymm14,%ymm14");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpand %ymm0,%ymm13,%ymm13");
			asm volatile("vpand %ymm0,%ymm15,%ymm15");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
			asm volatile("vmovdqa %0,%%ymm5" :: "m" (dptr[z][d]));
			asm volatile("vmovdqa %0,%%ymm7"
				     :: "m" (dptr[z][d+32]));
			asm volatile("vmovdqa %0,%%ymm13"
				     :: "m" (dptr[z][d+64]));
			asm volatile("vmovdqa %0,%%ymm15"
				     :: "m" (dptr[z][d+96]));
			asm volatile("vpxor %ymm5,%ymm2,%ymm2");
			asm volatile("vpxor %ymm7,%ymm3,%ymm3");
			asm volatile("vpxor %ymm13,%ymm10,%ymm10");
			asm volatile("vpxor %ymm15,%ymm11,%ymm11");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
		}
		asm volatile("prefetchnta %0" :: "m" (q[d]));
		asm volatile("prefetchnta %0" :: "m" (q[d+64]));
		for (z = start-1 ; z >= 0 ; z--) {
			asm volatile("vpxor %ymm5,%ymm5,%ymm5");
			asm volatile("vpxor %ymm7,%ymm7,%ymm7");
			asm volatile("vpxor %ymm13,%ymm13,%ymm13");
			asm volatile("vpxor %ymm15,%ymm15,%ymm15");
			asm volatile("vpcmpgtb %ymm4,%ymm5,%ymm5");
			asm volatile("vpcmpgtb %ymm6,%ymm7,%ymm7");
			asm volatile("vpcmpgtb %ymm12,%ymm13,%ymm13");
			asm volatile("vpcmpgtb %ymm14,%ymm15,%ymm15");
			asm volatile("vpaddb %ymm4,%ymm4,%ymm4");
			asm volatile("vpaddb %ymm6,%ymm6,%ymm6");
			asm volatile("vpaddb %ymm12,%ymm12,%ymm12");
			asm volatile("vpaddb %ymm14,%ymm14,%ymm14");
			asm volatile("vpand %ymm0,%ymm5,%ymm5");
			asm volatile("vpand %ymm0,%ymm7,%ymm7");
			asm volatile("vpand %ymm0,%ymm13,%ymm13");
			asm volatile("vpand %ymm0,%ymm15,%ymm15");
			asm volatile("vpxor %ymm5,%ymm4,%ymm4");
			asm volatile("vpxor %ymm7,%ymm6,%ymm6");
			asm volatile("vpxor %ymm13,%ymm12,%ymm12");
			asm volatile("vpxor %ymm15,%ymm14,%ymm14");
		}
		asm volatile("vmovntdq %%ymm2,%0" : "=m" (p[d]));
		asm volatile("vmovntdq %%ymm3,%0" : "=m" (p[d+32]));
		asm volatile("vmovntdq %%ymm10,%0" : "=m" (p[d+64]));
		asm volatile("vmovntdq %%ymm11,%0" : "=m" (p[d+96]));
		asm volatile("vpxor %0,%%ymm4,%%ymm4" : : "m" (q[d]));
		asm volatile("vpxor %0,%%ymm6,%%ymm6" : : "m" (q[d+32]));
		asm volatile("vpxor %0,%%ymm12,%%ymm12" : : "m" (q[d+64]));
		asm volatile("vpxor %0,%%ymm14,%%ymm14" : : "m" (q[d+96]));
		asm volatile("vmovntdq %%ymm4,%0" : "=m" (q[d]));
		asm volatile("vmovntdq %%ymm6,%0" : "=m" (q[d+32]));
		asm volatile("vmovntdq %%ymm12,%0" : "=m" (q[d+64]));
		asm volatile("vmovntdq %%ymm14,%0" : "=m" (q[d+96]));
	}
	asm volatile("sfence" : : : "memory");
	kernel_fpu_end();
}
