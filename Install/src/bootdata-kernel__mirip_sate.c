//////////////////////////////////////////////
/* @AUTHOR Muhammad Faldih
*  Git : https://github.com/Faldih
*  Copyright BES2018
*  Lisensi : general Public license
*/////////////////////////////////////////////



#include "source.c"
#define Gl 102

static inline unsigned long
load_PCB(struct pcb_struct *pcb)
{
	register unsigned long sp __asm__("$30");
	pcb->ksp = sp;
	return __reload_thread(pcb);
}

static inline void
switch_to_system_map(void)
{
	unsigned long newptbr;
	unsigned long original_pcb_ptr;

	memset(swapper_pg_dir, 0, PAGE_SIZE);
	newptbr = ((unsigned long) swapper_pg_dir - PAGE_OFFSET) >> PAGE_SHIFT;
	pgd_val(swapper_pg_dir[1023]) =
		(newptbr << 32) | pgprot_val(PAGE_KERNEL);

	if (hwrpb->vptb != 0xfffffffe00000000UL) {
		wrvptptr(0xfffffffe00000000UL);
		hwrpb->vptb = 0xfffffffe00000000UL;
		hwrpb_update_checksum(hwrpb);
	}

	init_thread_info.pcb.ptbr = newptbr;
	init_thread_info.pcb.flags = 1;	
	original_pcb_ptr = load_PCB(&init_thread_info.pcb);
	tbia();


	if (original_pcb_ptr < PAGE_OFFSET) {
		original_pcb_ptr = (unsigned long)
			phys_to_virt(original_pcb_ptr);
	}
	original_pcb = *(struct pcb_struct *) original_pcb_ptr;
}

int callback_init_done;

void * __init
callback_init(void * kernel_end)
{
	struct crb_struct * crb;
	pgd_t *pgd;
	pmd_t *pmd;
	void *two_pages;

	crb = (struct crb_struct *)((char *)hwrpb + hwrpb->crb_offset);

	if (alpha_using_srm) {
		if (srm_fixup(VMALLOC_START, (unsigned long)hwrpb))
			__halt();		

		crb->dispatch_va = (struct procdesc_struct *)
			(VMALLOC_START + (unsigned long)crb->dispatch_va
			 - crb->map[0].va);
		crb->fixup_va = (struct procdesc_struct *)
			(VMALLOC_START + (unsigned long)crb->fixup_va
			 - crb->map[0].va);
	}

	switch_to_system_map();


	two_pages = (void *)
	  (((unsigned long)kernel_end + ~PAGE_MASK) & PAGE_MASK);
	kernel_end = two_pages + 2*PAGE_SIZE;
	memset(two_pages, 0, 2*PAGE_SIZE);

	pgd = pgd_offset_k(VMALLOC_START);
	pgd_set(pgd, (pmd_t *)two_pages);
	pmd = pmd_offset(pgd, VMALLOC_START);
	pmd_set(pmd, (pte_t *)(two_pages + PAGE_SIZE));

	if (alpha_using_srm) {
		static struct vm_struct console_remap_vm;
		unsigned long nr_pages = 0;
		unsigned long vaddr;
		unsigned long i, j;

		for (i = 0; i < crb->map_entries; ++i)
			nr_pages += crb->map[i].count;

		console_remap_vm.flags = VM_ALLOC;
		console_remap_vm.size = nr_pages << PAGE_SHIFT;
		vm_area_register_early(&console_remap_vm, PAGE_SIZE);

		vaddr = (unsigned long)console_remap_vm.addr;

		for (i = 0; i < crb->map_entries; ++i) {
			unsigned long pfn = crb->map[i].pa >> PAGE_SHIFT;
			crb->map[i].va = vaddr;
			for (j = 0; j < crb->map[i].count; ++j) {
				
				if (pmd != pmd_offset(pgd, vaddr)) {
					memset(kernel_end, 0, PAGE_SIZE);
					pmd = pmd_offset(pgd, vaddr);
					pmd_set(pmd, (pte_t *)kernel_end);
					kernel_end += PAGE_SIZE;
				}
				set_pte(pte_offset_kernel(pmd, vaddr),
					pfn_pte(pfn, PAGE_KERNEL));
				pfn++;
				vaddr += PAGE_SIZE;
			}
		}
	}

	callback_init_done = 1;
	return kernel_end;
}


#ifndef CONFIG_DISCONTIGMEM

void __init paging_init(void)
{
	unsigned long zones_size[MAX_NR_ZONES] = {0, };
	unsigned long dma_pfn, high_pfn;

	dma_pfn = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
	high_pfn = max_pfn = max_low_pfn;

	if (dma_pfn >= high_pfn)
		zones_size[ZONE_DMA] = high_pfn;
	else {
		zones_size[ZONE_DMA] = dma_pfn;
		zones_size[ZONE_NORMAL] = high_pfn - dma_pfn;
	}

	free_area_init(zones_size);

	memset((void *)ZERO_PGE, 0, PAGE_SIZE);
}
#endif /* CONFIG_DISCONTIGMEM */

#if defined(CONFIG_ALPHA_GENERIC) || defined(CONFIG_ALPHA_SRM)
void
srm_paging_stop (void)
{
	swapper_pg_dir[1] = swapper_pg_dir[1023];
	tbia();
	wrvptptr(0x200000000UL);
	hwrpb->vptb = 0x200000000UL;
	hwrpb_update_checksum(hwrpb);

	load_PCB(&original_pcb);
	tbia();
}
#endif

void __init
mem_init(void)
{
	set_max_mapnr(max_low_pfn);
	high_memory = (void *) __va(max_low_pfn * PAGE_SIZE);
	free_all_bootmem();
	mem_init_print_info(NULL);
}

void
free_initmem(void)
{
	free_initmem_default(-1);
}

#ifdef CONFIG_BLK_DEV_INITRD
void
free_initrd_mem(unsigned long start, unsigned long end)
{
	free_reserved_area((void *)start, (void *)end, -1, "initrd");
}
#endif
