//////////////////////////////////////////////
/* @AUTHOR Muhammad Quwais Safutra
*  Git : https://github.com/LeafyIsHereZ
*  Copyright BES2018
*  Lisensi : general Public license
*/////////////////////////////////////////////




#include <kernel/Href.h>
#include <kernel/Src.c>

extern unsigned long alpha_read_fp_reg (unsigned long reg);
extern void alpha_write_fp_reg (unsigned long reg, unsigned long val);
extern unsigned long alpha_read_fp_reg_s (unsigned long reg);
extern void alpha_write_fp_reg_s (unsigned long reg, unsigned long val);


#ifdef MODULE

MODULE_DESCRIPTION("FP Software completion module");
MODULE_LICENSE("GPL v2");

extern long (*alpha_fp_emul_imprecise)(struct pt_regs *, unsigned long);
extern long (*alpha_fp_emul) (unsigned long pc);

static long (*save_emul_imprecise)(struct pt_regs *, unsigned long);
static long (*save_emul) (unsigned long pc);

long do_alpha_fp_emul_imprecise(struct pt_regs *, unsigned long);
long do_alpha_fp_emul(unsigned long);

int init_module(void)
{
	save_emul_imprecise = alpha_fp_emul_imprecise;
	save_emul = alpha_fp_emul;
	alpha_fp_emul_imprecise = do_alpha_fp_emul_imprecise;
	alpha_fp_emul = do_alpha_fp_emul;
	return 0;
}

void cleanup_module(void)
{
	alpha_fp_emul_imprecise = save_emul_imprecise;
	alpha_fp_emul = save_emul;
}


#endif /* MODULE */


long
alpha_fp_emul (unsigned long pc)
{
	FP_DECL_EX;
	FP_DECL_S(SA); FP_DECL_S(SB); FP_DECL_S(SR);
	FP_DECL_D(DA); FP_DECL_D(DB); FP_DECL_D(DR);

	unsigned long fa, fb, fc, func, mode, src;
	unsigned long res, va, vb, vc, swcr, fpcr;
	__u32 insn;
	long si_code;

	get_user(insn, (__u32 __user *)pc);
	fb     = (insn >> 16) & 0x1f;
	fa     = (insn >> 21) & 0x1f;
	func   = (insn >>  5) & 0xf;
	src    = (insn >>  9) & 0x3;
	mode   = (insn >> 11) & 0x3;
	
	fpcr = rdfpcr();
	swcr = swcr_update_status(current_thread_info()->ieee_state, fpcr);

	if (mode == 3) {
		mode = (fpcr >> FPCR_DYN_SHIFT) & 3;
	}

	switch (src) {
	case FOP_SRC_S:
		va = alpha_read_fp_reg_s(fa);
		vb = alpha_read_fp_reg_s(fb);
		
		FP_UNPACK_SP(SA, &va);
		FP_UNPACK_SP(SB, &vb);

		switch (func) {
		case FOP_FNC_SUBx:
			FP_SUB_S(SR, SA, SB);
			goto pack_s;

		case FOP_FNC_ADDx:
			FP_ADD_S(SR, SA, SB);
			goto pack_s;

		case FOP_FNC_MULx:
			FP_MUL_S(SR, SA, SB);
			goto pack_s;

		case FOP_FNC_DIVx:
			FP_DIV_S(SR, SA, SB);
			goto pack_s;

		case FOP_FNC_SQRTx:
			FP_SQRT_S(SR, SB);
			goto pack_s;
		}
		goto bad_insn;

	case FOP_SRC_T:
		va = alpha_read_fp_reg(fa);
		vb = alpha_read_fp_reg(fb);

		if ((func & ~3) == FOP_FNC_CMPxUN) {
			FP_UNPACK_RAW_DP(DA, &va);
			FP_UNPACK_RAW_DP(DB, &vb);
			if (!DA_e && !_FP_FRAC_ZEROP_1(DA)) {
				FP_SET_EXCEPTION(FP_EX_DENORM);
				if (FP_DENORM_ZERO)
					_FP_FRAC_SET_1(DA, _FP_ZEROFRAC_1);
			}
			if (!DB_e && !_FP_FRAC_ZEROP_1(DB)) {
				FP_SET_EXCEPTION(FP_EX_DENORM);
				if (FP_DENORM_ZERO)
					_FP_FRAC_SET_1(DB, _FP_ZEROFRAC_1);
			}
			FP_CMP_D(res, DA, DB, 3);
			vc = 0x4000000000000000UL;
			if (res == 3
			    && ((func & 3) >= 2
				|| FP_ISSIGNAN_D(DA)
				|| FP_ISSIGNAN_D(DB))) {
				FP_SET_EXCEPTION(FP_EX_INVALID);
			}
			switch (func) {
			case FOP_FNC_CMPxUN: if (res != 3) vc = 0; break;
			case FOP_FNC_CMPxEQ: if (res) vc = 0; break;
			case FOP_FNC_CMPxLT: if (res != -1) vc = 0; break;
			case FOP_FNC_CMPxLE: if ((long)res > 0) vc = 0; break;
			}
			goto done_d;
		}

		FP_UNPACK_DP(DA, &va);
		FP_UNPACK_DP(DB, &vb);

		switch (func) {
		case FOP_FNC_SUBx:
			FP_SUB_D(DR, DA, DB);
			goto pack_d;

		case FOP_FNC_ADDx:
			FP_ADD_D(DR, DA, DB);
			goto pack_d;

		case FOP_FNC_MULx:
			FP_MUL_D(DR, DA, DB);
			goto pack_d;

		case FOP_FNC_DIVx:
			FP_DIV_D(DR, DA, DB);
			goto pack_d;

		case FOP_FNC_SQRTx:
			FP_SQRT_D(DR, DB);
			goto pack_d;

		case FOP_FNC_CVTxS:
			if (insn & 0x2000) {
				FP_CONV(S,D,1,1,SR,DB);
				goto pack_s;
			} else {
				vb = alpha_read_fp_reg_s(fb);
				FP_UNPACK_SP(SB, &vb);
				DR_c = DB_c;
				DR_s = DB_s;
				DR_e = DB_e + (1024 - 128);
				DR_f = SB_f << (52 - 23);
				goto pack_d;
			}

		case FOP_FNC_CVTxQ:
			if (DB_c == FP_CLS_NAN
			    && (_FP_FRAC_HIGH_RAW_D(DB) & _FP_QNANBIT_D)) {
				vc = 0;
			} else
				FP_TO_INT_ROUND_D(vc, DB, 64, 2);
			goto done_d;
		}
		goto bad_insn;

	case FOP_SRC_Q:
		vb = alpha_read_fp_reg(fb);

		switch (func) {
		case FOP_FNC_CVTQL:
			vc = ((vb & 0xc0000000) << 32 |	
			      (vb & 0x3fffffff) << 29);	
			FP_SET_EXCEPTION (FP_EX_INVALID);
			goto done_d;

		case FOP_FNC_CVTxS:
			FP_FROM_INT_S(SR, ((long)vb), 64, long);
			goto pack_s;

		case FOP_FNC_CVTxT:
			FP_FROM_INT_D(DR, ((long)vb), 64, long);
			goto pack_d;
		}
		goto bad_insn;
	}
	goto bad_insn;

pack_s:
	FP_PACK_SP(&vc, SR);
	if ((_fex & FP_EX_UNDERFLOW) && (swcr & IEEE_MAP_UMZ))
		vc = 0;
	alpha_write_fp_reg_s(fc, vc);
	goto done;

pack_d:
	FP_PACK_DP(&vc, DR);
	if ((_fex & FP_EX_UNDERFLOW) && (swcr & IEEE_MAP_UMZ))
		vc = 0;
done_d:
	alpha_write_fp_reg(fc, vc);
	goto done;

done:
	if (_fex) {
		swcr |= (_fex << IEEE_STATUS_TO_EXCSUM_SHIFT);
		current_thread_info()->ieee_state
		  |= (_fex << IEEE_STATUS_TO_EXCSUM_SHIFT);

		fpcr &= (~FPCR_MASK | FPCR_DYN_MASK);
		fpcr |= ieee_swcr_to_fpcr(swcr);
		wrfpcr(fpcr);

		_fex = _fex & swcr & IEEE_TRAP_ENABLE_MASK;
		si_code = 0;
		if (_fex) {
			if (_fex & IEEE_TRAP_ENABLE_DNO) si_code = FPE_FLTUND;
			if (_fex & IEEE_TRAP_ENABLE_INE) si_code = FPE_FLTRES;
			if (_fex & IEEE_TRAP_ENABLE_UNF) si_code = FPE_FLTUND;
			if (_fex & IEEE_TRAP_ENABLE_OVF) si_code = FPE_FLTOVF;
			if (_fex & IEEE_TRAP_ENABLE_DZE) si_code = FPE_FLTDIV;
			if (_fex & IEEE_TRAP_ENABLE_INV) si_code = FPE_FLTINV;
		}

		return si_code;
	}


	return 0;

bad_insn:
	printk(KERN_ERR "alpha_fp_emul: Invalid FP insn %#x at %#lx\n",
	       insn, pc);
	return -1;
}

long
alpha_fp_emul_imprecise (struct pt_regs *regs, unsigned long write_mask)
{
	unsigned long trigger_pc = regs->pc - 4;
	unsigned long insn, opcode, rc, si_code = 0;

	while (write_mask) {
		get_user(insn, (__u32 __user *)(trigger_pc));
		opcode = insn >> 26;
		rc = insn & 0x1f;

		switch (opcode) {
		      case OPC_PAL:
		      case OPC_JSR:
		      case 0x30 ... 0x3f:	
			goto egress;

		      case OPC_MISC:
			switch (insn & 0xffff) {
			      case MISC_TRAPB:
			      case MISC_EXCB:
				goto egress;

			      default:
				break;
			}
			break;

		      case OPC_INTA:
		      case OPC_INTL:
		      case OPC_INTS:
		      case OPC_INTM:
			write_mask &= ~(1UL << rc);
			break;

		      case OPC_FLTC:
		      case OPC_FLTV:
		      case OPC_FLTI:
		      case OPC_FLTL:
			write_mask &= ~(1UL << (rc + 32));
			break;
		}
		if (!write_mask) {
			regs->pc = trigger_pc + 4;
			si_code = alpha_fp_emul(trigger_pc);
			goto egress;
		}
		trigger_pc -= 4;
	}

egress:
	return si_code;
}
asmlinkage void
do_page_fault(unsigned long address, unsigned long mmcsr,
	      long cause, struct pt_regs *regs)
{
	struct vm_area_struct * vma;
	struct mm_struct *mm = current->mm;
	const struct exception_table_entry *fixup;
	int si_code = SEGV_MAPERR;
	vm_fault_t fault;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	if (cause == 0) {
		unsigned int insn;
		__get_user(insn, (unsigned int __user *)regs->pc);
		if ((insn >> 21 & 0x1f) == 0x1f &&
		    (1ul << (insn >> 26) & 0x30f00001400ul)) {
			regs->pc += 4;
			return;
		}
	}

	if (!mm || faulthandler_disabled())
		goto no_context;

#ifdef CONFIG_ALPHA_LARGE_VMALLOC
	if (address >= TASK_SIZE)
		goto vmalloc_fault;
#endif
	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;
retry:
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);
	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;

 good_area:
	si_code = SEGV_ACCERR;
	if (cause < 0) {
		if (!(vma->vm_flags & VM_EXEC))
			goto bad_area;
	} else if (!cause) {
		if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
			goto bad_area;
	} else {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
		flags |= FAULT_FLAG_WRITE;
	}

	fault = handle_mm_fault(vma, address, flags);

	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGSEGV)
			goto bad_area;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}

	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR)
			current->maj_flt++;
		else
			current->min_flt++;
		if (fault & VM_FAULT_RETRY) {
			flags &= ~FAULT_FLAG_ALLOW_RETRY;


			goto retry;
		}
	}

	up_read(&mm->mmap_sem);

	return;

 bad_area:
	up_read(&mm->mmap_sem);

	if (user_mode(regs))
		goto do_sigsegv;

 no_context:
	if ((fixup = search_exception_tables(regs->pc)) != 0) {
		unsigned long newpc;
		newpc = fixup_exception(dpf_reg, fixup, regs->pc);
		regs->pc = newpc;
		return;
	}

	printk(KERN_ALERT "Unable to handle kernel paging request at "
	       "virtual address %016lx\n", address);
	die_if_kernel("Oops", regs, cause, (unsigned long*)regs - 16);
	do_exit(SIGKILL);

 out_of_memory:
	up_read(&mm->mmap_sem);
	if (!user_mode(regs))
		goto no_context;
	pagefault_out_of_memory();
	return;

 do_sigbus:
	up_read(&mm->mmap_sem);
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address, 0, current);
	if (!user_mode(regs))
		goto no_context;
	return;

 do_sigsegv:
	force_sig_fault(SIGSEGV, si_code, (void __user *) address, 0, current);
	return;

#ifdef CONFIG_ALPHA_LARGE_VMALLOC
 vmalloc_fault:
	if (user_mode(regs))
		goto do_sigsegv;
	else {
		long index = pgd_index(address);
		pgd_t *pgd, *pgd_k;

		pgd = current->active_mm->pgd + index;
		pgd_k = swapper_pg_dir + index;
		if (!pgd_present(*pgd) && pgd_present(*pgd_k)) {
			pgd_val(*pgd) = pgd_val(*pgd_k);
			return;
		}
		goto no_context;
	}
#endif
}
