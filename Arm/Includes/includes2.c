#include "Backship.c"
#include "git.h"

#define	op_t	unsigned long int
#define OPSIZ	(sizeof(op_t))

#define	reg_char	char

#define MERGE(w0, sh_1, w1, sh_2) (((w0) >> (sh_1)) | ((w1) << (sh_2)))


#define BYTE_COPY_FWD(dst_bp, src_bp, nbytes)				\
do {									\
	size_t __nbytes = (nbytes);					\
	while (__nbytes > 0) {						\
		unsigned char __x = ((unsigned char *) src_bp)[0];	\
		src_bp += 1;						\
		__nbytes -= 1;						\
		((unsigned char *) dst_bp)[0] = __x;			\
		dst_bp += 1;						\
	}								\
} while (0)


#define WORD_COPY_FWD(dst_bp, src_bp, nbytes_left, nbytes)		\
do {									\
	if (src_bp % OPSIZ == 0)					\
		_wordcopy_fwd_aligned(dst_bp, src_bp, (nbytes) / OPSIZ);\
	else								\
		_wordcopy_fwd_dest_aligned(dst_bp, src_bp, (nbytes) / OPSIZ);\
	src_bp += (nbytes) & -OPSIZ;					\
	dst_bp += (nbytes) & -OPSIZ;					\
	(nbytes_left) = (nbytes) % OPSIZ;				\
} while (0)

#define	OP_T_THRES	16

static void _wordcopy_fwd_aligned(long int dstp, long int srcp, size_t len)
{
	while (len > 7) {
		register op_t a0, a1, a2, a3, a4, a5, a6, a7;

		a0 = ((op_t *) srcp)[0];
		a1 = ((op_t *) srcp)[1];
		a2 = ((op_t *) srcp)[2];
		a3 = ((op_t *) srcp)[3];
		a4 = ((op_t *) srcp)[4];
		a5 = ((op_t *) srcp)[5];
		a6 = ((op_t *) srcp)[6];
		a7 = ((op_t *) srcp)[7];
		((op_t *) dstp)[0] = a0;
		((op_t *) dstp)[1] = a1;
		((op_t *) dstp)[2] = a2;
		((op_t *) dstp)[3] = a3;
		((op_t *) dstp)[4] = a4;
		((op_t *) dstp)[5] = a5;
		((op_t *) dstp)[6] = a6;
		((op_t *) dstp)[7] = a7;

		srcp += 8 * OPSIZ;
		dstp += 8 * OPSIZ;
		len -= 8;
	}
	while (len > 0) {
		*(op_t *)dstp = *(op_t *)srcp;

		srcp += OPSIZ;
		dstp += OPSIZ;
		len -= 1;
	}
}
static void _wordcopy_fwd_dest_aligned(long int dstp, long int srcp,
					size_t len)
{
	op_t ap;
	int sh_1, sh_2;

	sh_1 = 8 * (srcp % OPSIZ);
	sh_2 = 8 * OPSIZ - sh_1;
	srcp &= -OPSIZ;
	ap = ((op_t *) srcp)[0];
	srcp += OPSIZ;

	while (len > 3) {
		op_t a0, a1, a2, a3;

		a0 = ((op_t *) srcp)[0];
		a1 = ((op_t *) srcp)[1];
		a2 = ((op_t *) srcp)[2];
		a3 = ((op_t *) srcp)[3];
		((op_t *) dstp)[0] = MERGE(ap, sh_1, a0, sh_2);
		((op_t *) dstp)[1] = MERGE(a0, sh_1, a1, sh_2);
		((op_t *) dstp)[2] = MERGE(a1, sh_1, a2, sh_2);
		((op_t *) dstp)[3] = MERGE(a2, sh_1, a3, sh_2);

		ap = a3;
		srcp += 4 * OPSIZ;
		dstp += 4 * OPSIZ;
		len -= 4;
	}
	while (len > 0) {
		register op_t a0;

		a0 = ((op_t *) srcp)[0];
		((op_t *) dstp)[0] = MERGE(ap, sh_1, a0, sh_2);

		ap = a0;
		srcp += OPSIZ;
		dstp += OPSIZ;
		len -= 1;
	}
}

void *memcpy(void *dstpp, const void *srcpp, size_t len)
{
	unsigned long int dstp = (long int) dstpp;
	unsigned long int srcp = (long int) srcpp;
	if (len >= OP_T_THRES) {
		len -= (-dstp) % OPSIZ;
		BYTE_COPY_FWD(dstp, srcp, (-dstp) % OPSIZ);

		

		WORD_COPY_FWD(dstp, srcp, len, len);
	}
	BYTE_COPY_FWD(dstp, srcp, len);

	return dstpp;
}

void *memcpyb(void *dstpp, const void *srcpp, unsigned len)
{
	unsigned long int dstp = (long int) dstpp;
	unsigned long int srcp = (long int) srcpp;

	BYTE_COPY_FWD(dstp, srcp, len);

	return dstpp;
}     
