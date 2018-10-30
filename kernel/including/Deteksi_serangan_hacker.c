#include "Terminal.c"

struct dma_coherent_mem {
	void		*virt_base;
	dma_addr_t	device_base;
	unsigned long	pfn_base;
	int		size;
	int		flags;
	unsigned long	*bitmap;
	spinlock_t	spinlock;
	bool		use_dev_dma_pfn_offset;
};

static struct dma_coherent_mem *dma_coherent_default_memory __ro_after_init;

static inline struct dma_coherent_mem *dev_get_coherent_memory(struct device *dev)
{
	if (dev && dev->dma_mem)
		return dev->dma_mem;
	return NULL;
}

static inline dma_addr_t dma_get_device_base(struct device *dev,
					     struct dma_coherent_mem * mem)
{
	if (mem->use_dev_dma_pfn_offset)
		return (mem->pfn_base - dev->dma_pfn_offset) << PAGE_SHIFT;
	else
		return mem->device_base;
}

static int dma_init_coherent_memory(
	phys_addr_t phys_addr, dma_addr_t device_addr, size_t size, int flags,
	struct dma_coherent_mem **mem)
{
	struct dma_coherent_mem *dma_mem = NULL;
	void __iomem *mem_base = NULL;
	int pages = size >> PAGE_SHIFT;
	int bitmap_size = BITS_TO_LONGS(pages) * sizeof(long);
	int ret;

	if (!size) {
		ret = -EINVAL;
		goto out;
	}

	mem_base = memremap(phys_addr, size, MEMREMAP_WC);
	if (!mem_base) {
		ret = -EINVAL;
		goto out;
	}
	dma_mem = kzalloc(sizeof(struct dma_coherent_mem), GFP_KERNEL);
	if (!dma_mem) {
		ret = -ENOMEM;
		goto out;
	}
	dma_mem->bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!dma_mem->bitmap) {
		ret = -ENOMEM;
		goto out;
	}

	dma_mem->virt_base = mem_base;
	dma_mem->device_base = device_addr;
	dma_mem->pfn_base = PFN_DOWN(phys_addr);
	dma_mem->size = pages;
	dma_mem->flags = flags;
	spin_lock_init(&dma_mem->spinlock);

	*mem = dma_mem;
	return 0;

out:
	kfree(dma_mem);
	if (mem_base)
		memunmap(mem_base);
	return ret;
}

static void dma_release_coherent_memory(struct dma_coherent_mem *mem)
{
	if (!mem)
		return;

	memunmap(mem->virt_base);
	kfree(mem->bitmap);
	kfree(mem);
}

static int dma_assign_coherent_memory(struct device *dev,
				      struct dma_coherent_mem *mem)
{
	if (!dev)
		return -ENODEV;

	if (dev->dma_mem)
		return -EBUSY;

	dev->dma_mem = mem;
	return 0;
}

int dma_declare_coherent_memory(struct device *dev, phys_addr_t phys_addr,
				dma_addr_t device_addr, size_t size, int flags)
{
	struct dma_coherent_mem *mem;
	int ret;

	ret = dma_init_coherent_memory(phys_addr, device_addr, size, flags, &mem);
	if (ret)
		return ret;

	ret = dma_assign_coherent_memory(dev, mem);
	if (ret)
		dma_release_coherent_memory(mem);
	return ret;
}
EXPORT_SYMBOL(dma_declare_coherent_memory);

void dma_release_declared_memory(struct device *dev)
{
	struct dma_coherent_mem *mem = dev->dma_mem;

	if (!mem)
		return;
	dma_release_coherent_memory(mem);
	dev->dma_mem = NULL;
}
EXPORT_SYMBOL(dma_release_declared_memory);

void *dma_mark_declared_memory_occupied(struct device *dev,
					dma_addr_t device_addr, size_t size)
{
	struct dma_coherent_mem *mem = dev->dma_mem;
	unsigned long flags;
	int pos, err;

	size += device_addr & ~PAGE_MASK;

	if (!mem)
		return ERR_PTR(-EINVAL);

	spin_lock_irqsave(&mem->spinlock, flags);
	pos = PFN_DOWN(device_addr - dma_get_device_base(dev, mem));
	err = bitmap_allocate_region(mem->bitmap, pos, get_order(size));
	spin_unlock_irqrestore(&mem->spinlock, flags);

	if (err != 0)
		return ERR_PTR(err);
	return mem->virt_base + (pos << PAGE_SHIFT);
}
EXPORT_SYMBOL(dma_mark_declared_memory_occupied);

static void *__dma_alloc_from_coherent(struct dma_coherent_mem *mem,
		ssize_t size, dma_addr_t *dma_handle)
{
	int order = get_order(size);
	unsigned long flags;
	int pageno;
	void *ret;

	spin_lock_irqsave(&mem->spinlock, flags);

	if (unlikely(size > (mem->size << PAGE_SHIFT)))
		goto err;

	pageno = bitmap_find_free_region(mem->bitmap, mem->size, order);
	if (unlikely(pageno < 0))
		goto err;
	*dma_handle = mem->device_base + (pageno << PAGE_SHIFT);
	ret = mem->virt_base + (pageno << PAGE_SHIFT);
	spin_unlock_irqrestore(&mem->spinlock, flags);
	memset(ret, 0, size);
	return ret;
err:
	spin_unlock_irqrestore(&mem->spinlock, flags);
	return NULL;
}
int dma_alloc_from_dev_coherent(struct device *dev, ssize_t size,
		dma_addr_t *dma_handle, void **ret)
{
	struct dma_coherent_mem *mem = dev_get_coherent_memory(dev);

	if (!mem)
		return 0;

	*ret = __dma_alloc_from_coherent(mem, size, dma_handle);
	if (*ret)
		return 1;
	return mem->flags & DMA_MEMORY_EXCLUSIVE;
}
EXPORT_SYMBOL(dma_alloc_from_dev_coherent);

void *dma_alloc_from_global_coherent(ssize_t size, dma_addr_t *dma_handle)
{
	if (!dma_coherent_default_memory)
		return NULL;

	return __dma_alloc_from_coherent(dma_coherent_default_memory, size,
			dma_handle);
}

static int __dma_release_from_coherent(struct dma_coherent_mem *mem,
				       int order, void *vaddr)
{
	if (mem && vaddr >= mem->virt_base && vaddr <
		   (mem->virt_base + (mem->size << PAGE_SHIFT))) {
		int page = (vaddr - mem->virt_base) >> PAGE_SHIFT;
		unsigned long flags;

		spin_lock_irqsave(&mem->spinlock, flags);
		bitmap_release_region(mem->bitmap, page, order);
		spin_unlock_irqrestore(&mem->spinlock, flags);
		return 1;
	}
	return 0;
}
int dma_release_from_dev_coherent(struct device *dev, int order, void *vaddr)
{
	struct dma_coherent_mem *mem = dev_get_coherent_memory(dev);

	return __dma_release_from_coherent(mem, order, vaddr);
}
EXPORT_SYMBOL(dma_release_from_dev_coherent);

int dma_release_from_global_coherent(int order, void *vaddr)
{
	if (!dma_coherent_default_memory)
		return 0;

	return __dma_release_from_coherent(dma_coherent_default_memory, order,
			vaddr);
}

static int __dma_mmap_from_coherent(struct dma_coherent_mem *mem,
		struct vm_area_struct *vma, void *vaddr, size_t size, int *ret)
{
	if (mem && vaddr >= mem->virt_base && vaddr + size <=
		   (mem->virt_base + (mem->size << PAGE_SHIFT))) {
		unsigned long off = vma->vm_pgoff;
		int start = (vaddr - mem->virt_base) >> PAGE_SHIFT;
		int user_count = vma_pages(vma);
		int count = PAGE_ALIGN(size) >> PAGE_SHIFT;

		*ret = -ENXIO;
		if (off < count && user_count <= count - off) {
			unsigned long pfn = mem->pfn_base + start + off;
			*ret = remap_pfn_range(vma, vma->vm_start, pfn,
					       user_count << PAGE_SHIFT,
					       vma->vm_page_prot);
		}
		return 1;
	}
	return 0;
}
int dma_mmap_from_dev_coherent(struct device *dev, struct vm_area_struct *vma,
			   void *vaddr, size_t size, int *ret)
{
	struct dma_coherent_mem *mem = dev_get_coherent_memory(dev);

	return __dma_mmap_from_coherent(mem, vma, vaddr, size, ret);
}
EXPORT_SYMBOL(dma_mmap_from_dev_coherent);

int dma_mmap_from_global_coherent(struct vm_area_struct *vma, void *vaddr,
				   size_t size, int *ret)
{
	if (!dma_coherent_default_memory)
		return 0;

	return __dma_mmap_from_coherent(dma_coherent_default_memory, vma,
					vaddr, size, ret);
}

static struct reserved_mem *dma_reserved_default_memory __initdata;

static int rmem_dma_device_init(struct reserved_mem *rmem, struct device *dev)
{
	struct dma_coherent_mem *mem = rmem->priv;
	int ret;

	if (!mem) {
		ret = dma_init_coherent_memory(rmem->base, rmem->base,
					       rmem->size,
					       DMA_MEMORY_EXCLUSIVE, &mem);
		if (ret) {
			pr_err("Reserved memory: failed to init DMA memory pool at %pa, size %ld MiB\n",
				&rmem->base, (unsigned long)rmem->size / SZ_1M);
			return ret;
		}
	}
	mem->use_dev_dma_pfn_offset = true;
	rmem->priv = mem;
	dma_assign_coherent_memory(dev, mem);
	return 0;
}

static void rmem_dma_device_release(struct reserved_mem *rmem,
				    struct device *dev)
{
	if (dev)
		dev->dma_mem = NULL;
}

static const struct reserved_mem_ops rmem_dma_ops = {
	.device_init	= rmem_dma_device_init,
	.device_release	= rmem_dma_device_release,
};

static int __init rmem_dma_setup(struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;

	if (of_get_flat_dt_prop(node, "reusable", NULL))
		return -EINVAL;

#ifdef CONFIG_ARM
	if (!of_get_flat_dt_prop(node, "no-map", NULL)) {
		pr_err("Reserved memory: regions without no-map are not yet supported\n");
		return -EINVAL;
	}

	if (of_get_flat_dt_prop(node, "linux,dma-default", NULL)) {
		WARN(dma_reserved_default_memory,
		     "Reserved memory: region for default DMA coherent area is redefined\n");
		dma_reserved_default_memory = rmem;
	}
#endif

	rmem->ops = &rmem_dma_ops;
	pr_info("Reserved memory: created DMA memory pool at %pa, size %ld MiB\n",
		&rmem->base, (unsigned long)rmem->size / SZ_1M);
	return 0;
}

static int __init dma_init_reserved_memory(void)
{
	const struct reserved_mem_ops *ops;
	int ret;

	if (!dma_reserved_default_memory)
		return -ENOMEM;

	ops = dma_reserved_default_memory->ops;
	ret = ops->device_init(dma_reserved_default_memory, NULL);

	if (!ret) {
		dma_coherent_default_memory = dma_reserved_default_memory->priv;
		pr_info("DMA: default coherent area is set\n");
	}

	return ret;
}

core_initcall(dma_init_reserved_memory);

RESERVEDMEM_OF_DECLARE(dma, "shared-dma-pool", rmem_dma_setup);
#endif

static const phys_addr_t size_bytes = (phys_addr_t)CMA_SIZE_MBYTES * SZ_1M;
static phys_addr_t size_cmdline = -1;
static phys_addr_t base_cmdline;
static phys_addr_t limit_cmdline;

static int __init early_cma(char *p)
{
	if (!p) {
		pr_err("Config string not provided\n");
		return -EINVAL;
	}

	size_cmdline = memparse(p, &p);
	if (*p != '@')
		return 0;
	base_cmdline = memparse(p + 1, &p);
	if (*p != '-') {
		limit_cmdline = base_cmdline + size_cmdline;
		return 0;
	}
	limit_cmdline = memparse(p + 1, &p);

	return 0;
}
early_param("cma", early_cma);

#ifdef CONFIG_CMA_SIZE_PERCENTAGE

static phys_addr_t __init __maybe_unused cma_early_percent_memory(void)
{
	struct memblock_region *reg;
	unsigned long total_pages = 0;
	for_each_memblock(memory, reg)
		total_pages += memblock_region_memory_end_pfn(reg) -
			       memblock_region_memory_base_pfn(reg);

	return (total_pages * CONFIG_CMA_SIZE_PERCENTAGE / 100) << PAGE_SHIFT;
}

#else

static inline __maybe_unused phys_addr_t cma_early_percent_memory(void)
{
	return 0;
}

#endif
void __init dma_contiguous_reserve(phys_addr_t limit)
{
	phys_addr_t selected_size = 0;
	phys_addr_t selected_base = 0;
	phys_addr_t selected_limit = limit;
	bool fixed = false;

	pr_debug("%s(limit %08lx)\n", __func__, (unsigned long)limit);

	if (size_cmdline != -1) {
		selected_size = size_cmdline;
		selected_base = base_cmdline;
		selected_limit = min_not_zero(limit_cmdline, limit);
		if (base_cmdline + size_cmdline == limit_cmdline)
			fixed = true;
	} else {
#ifdef CONFIG_CMA_SIZE_SEL_MBYTES
		selected_size = size_bytes;
#elif defined(CONFIG_CMA_SIZE_SEL_PERCENTAGE)
		selected_size = cma_early_percent_memory();
#elif defined(CONFIG_CMA_SIZE_SEL_MIN)
		selected_size = min(size_bytes, cma_early_percent_memory());
#elif defined(CONFIG_CMA_SIZE_SEL_MAX)
		selected_size = max(size_bytes, cma_early_percent_memory());
#endif
	}

	if (selected_size && !dma_contiguous_default_area) {
		pr_debug("%s: reserving %ld MiB for global area\n", __func__,
			 (unsigned long)selected_size / SZ_1M);

		dma_contiguous_reserve_area(selected_size, selected_base,
					    selected_limit,
					    &dma_contiguous_default_area,
					    fixed);
	}
}
int __init dma_contiguous_reserve_area(phys_addr_t size, phys_addr_t base,
				       phys_addr_t limit, struct cma **res_cma,
				       bool fixed)
{
	int ret;

	ret = cma_declare_contiguous(base, size, limit, 0, 0, fixed,
					"reserved", res_cma);
	if (ret)
		return ret;
	dma_contiguous_early_fixup(cma_get_base(*res_cma),
				cma_get_size(*res_cma));

	return 0;
}
struct page *dma_alloc_from_contiguous(struct device *dev, size_t count,
				       unsigned int align, bool no_warn)
{
	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	return cma_alloc(dev_get_cma_area(dev), count, align, no_warn);
}
bool dma_release_from_contiguous(struct device *dev, struct page *pages,
				 int count)
{
	return cma_release(dev_get_cma_area(dev), pages, count);
}

static int rmem_cma_device_init(struct reserved_mem *rmem, struct device *dev)
{
	dev_set_cma_area(dev, rmem->priv);
	return 0;
}

static void rmem_cma_device_release(struct reserved_mem *rmem,
				    struct device *dev)
{
	dev_set_cma_area(dev, NULL);
}

static const struct reserved_mem_ops rmem_cma_ops = {
	.device_init	= rmem_cma_device_init,
	.device_release = rmem_cma_device_release,
};

static int __init rmem_cma_setup(struct reserved_mem *rmem)
{
	phys_addr_t align = PAGE_SIZE << max(MAX_ORDER - 1, pageblock_order);
	phys_addr_t mask = align - 1;
	unsigned long node = rmem->fdt_node;
	struct cma *cma;
	int err;

	if (!of_get_flat_dt_prop(node, "reusable", NULL) ||
	    of_get_flat_dt_prop(node, "no-map", NULL))
		return -EINVAL;

	if ((rmem->base & mask) || (rmem->size & mask)) {
		pr_err("Reserved memory: incorrect alignment of CMA region\n");
		return -EINVAL;
	}

	err = cma_init_reserved_mem(rmem->base, rmem->size, 0, rmem->name, &cma);
	if (err) {
		pr_err("Reserved memory: unable to setup CMA region\n");
		return err;
	}
	dma_contiguous_early_fixup(rmem->base, rmem->size);

	if (of_get_flat_dt_prop(node, "linux,cma-default", NULL))
		dma_contiguous_set_default(cma);

	rmem->ops = &rmem_cma_ops;
	rmem->priv = cma;

	pr_info("Reserved memory: created CMA memory pool at %pa, size %ld MiB\n",
		&rmem->base, (unsigned long)rmem->size / SZ_1M);

	return 0;
}

struct dma_debug_entry {
	struct list_head list;
	struct device    *dev;
	int              type;
	unsigned long	 pfn;
	size_t		 offset;
	u64              dev_addr;
	u64              size;
	int              direction;
	int		 sg_call_ents;
	int		 sg_mapped_ents;
	enum map_err_types  map_err_type;
#ifdef CONFIG_STACKTRACE
	struct		 stack_trace stacktrace;
	unsigned long	 st_entries[DMA_DEBUG_STACKTRACE_ENTRIES];
#endif
};

typedef bool (*match_fn)(struct dma_debug_entry *, struct dma_debug_entry *);

struct hash_bucket {
	struct list_head list;
	spinlock_t lock;
} ____cacheline_aligned_in_smp;

/* Hash list to save the allocated dma addresses */
static struct hash_bucket dma_entry_hash[HASH_SIZE];
/* List of pre-allocated dma_debug_entry's */
static LIST_HEAD(free_entries);
/* Lock for the list above */
static DEFINE_SPINLOCK(free_entries_lock);

/* Global disable flag - will be set in case of an error */
static bool global_disable __read_mostly;

/* Early initialization disable flag, set at the end of dma_debug_init */
static bool dma_debug_initialized __read_mostly;

static inline bool dma_debug_disabled(void)
{
	return global_disable || !dma_debug_initialized;
}

/* Global error count */
static u32 error_count;

/* Global error show enable*/
static u32 show_all_errors __read_mostly;
/* Number of errors to show */
static u32 show_num_errors = 1;

static u32 num_free_entries;
static u32 min_free_entries;
static u32 nr_total_entries;

/* number of preallocated entries requested by kernel cmdline */
static u32 nr_prealloc_entries = PREALLOC_DMA_DEBUG_ENTRIES;

/* debugfs dentry's for the stuff above */
static struct dentry *dma_debug_dent        __read_mostly;
static struct dentry *global_disable_dent   __read_mostly;
static struct dentry *error_count_dent      __read_mostly;
static struct dentry *show_all_errors_dent  __read_mostly;
static struct dentry *show_num_errors_dent  __read_mostly;
static struct dentry *num_free_entries_dent __read_mostly;
static struct dentry *min_free_entries_dent __read_mostly;
static struct dentry *filter_dent           __read_mostly;

/* per-driver filter related state */

#define NAME_MAX_LEN	64

static char                  current_driver_name[NAME_MAX_LEN] __read_mostly;
static struct device_driver *current_driver                    __read_mostly;

static DEFINE_RWLOCK(driver_name_lock);

static const char *const maperr2str[] = {
	[MAP_ERR_CHECK_NOT_APPLICABLE] = "dma map error check not applicable",
	[MAP_ERR_NOT_CHECKED] = "dma map error not checked",
	[MAP_ERR_CHECKED] = "dma map error checked",
};

static const char *type2name[5] = { "single", "page",
				    "scather-gather", "coherent",
				    "resource" };

static const char *dir2name[4] = { "DMA_BIDIRECTIONAL", "DMA_TO_DEVICE",
				   "DMA_FROM_DEVICE", "DMA_NONE" };

/*
 * The access to some variables in this macro is racy. We can't use atomic_t
 * here because all these variables are exported to debugfs. Some of them even
 * writeable. This is also the reason why a lock won't help much. But anyway,
 * the races are no big deal. Here is why:
 *
 *   error_count: the addition is racy, but the worst thing that can happen is
 *                that we don't count some errors
 *   show_num_errors: the subtraction is racy. Also no big deal because in
 *                    worst case this will result in one warning more in the
 *                    system log than the user configured. This variable is
 *                    writeable via debugfs.
 */
static inline void dump_entry_trace(struct dma_debug_entry *entry)
{
#ifdef CONFIG_STACKTRACE
	if (entry) {
		pr_warning("Mapped at:\n");
		print_stack_trace(&entry->stacktrace, 0);
	}
#endif
}

static bool driver_filter(struct device *dev)
{
	struct device_driver *drv;
	unsigned long flags;
	bool ret;

	/* driver filter off */
	if (likely(!current_driver_name[0]))
		return true;

	/* driver filter on and initialized */
	if (current_driver && dev && dev->driver == current_driver)
		return true;

	/* driver filter on, but we can't filter on a NULL device... */
	if (!dev)
		return false;

	if (current_driver || !current_driver_name[0])
		return false;

	/* driver filter on but not yet initialized */
	drv = dev->driver;
	if (!drv)
		return false;

	/* lock to protect against change of current_driver_name */
	read_lock_irqsave(&driver_name_lock, flags);

	ret = false;
	if (drv->name &&
	    strncmp(current_driver_name, drv->name, NAME_MAX_LEN - 1) == 0) {
		current_driver = drv;
		ret = true;
	}

	read_unlock_irqrestore(&driver_name_lock, flags);

	return ret;
}

#define err_printk(dev, entry, format, arg...) do {			\
		error_count += 1;					\
		if (driver_filter(dev) &&				\
		    (show_all_errors || show_num_errors > 0)) {		\
			WARN(1, "%s %s: " format,			\
			     dev ? dev_driver_string(dev) : "NULL",	\
			     dev ? dev_name(dev) : "NULL", ## arg);	\
			dump_entry_trace(entry);			\
		}							\
		if (!show_all_errors && show_num_errors > 0)		\
			show_num_errors -= 1;				\
	} while (0);

/*
 * Hash related functions
 *
 * Every DMA-API request is saved into a struct dma_debug_entry. To
 * have quick access to these structs they are stored into a hash.
 */
static int hash_fn(struct dma_debug_entry *entry)
{
	/*
	 * Hash function is based on the dma address.
	 * We use bits 20-27 here as the index into the hash
	 */
	return (entry->dev_addr >> HASH_FN_SHIFT) & HASH_FN_MASK;
}

/*
 * Request exclusive access to a hash bucket for a given dma_debug_entry.
 */
static struct hash_bucket *get_hash_bucket(struct dma_debug_entry *entry,
					   unsigned long *flags)
	__acquires(&dma_entry_hash[idx].lock)
{
	int idx = hash_fn(entry);
	unsigned long __flags;

	spin_lock_irqsave(&dma_entry_hash[idx].lock, __flags);
	*flags = __flags;
	return &dma_entry_hash[idx];
}

/*
 * Give up exclusive access to the hash bucket
 */
static void put_hash_bucket(struct hash_bucket *bucket,
			    unsigned long *flags)
	__releases(&bucket->lock)
{
	unsigned long __flags = *flags;

	spin_unlock_irqrestore(&bucket->lock, __flags);
}

static bool exact_match(struct dma_debug_entry *a, struct dma_debug_entry *b)
{
	return ((a->dev_addr == b->dev_addr) &&
		(a->dev == b->dev)) ? true : false;
}

static bool containing_match(struct dma_debug_entry *a,
			     struct dma_debug_entry *b)
{
	if (a->dev != b->dev)
		return false;

	if ((b->dev_addr <= a->dev_addr) &&
	    ((b->dev_addr + b->size) >= (a->dev_addr + a->size)))
		return true;

	return false;
}

/*
 * Search a given entry in the hash bucket list
 */
static struct dma_debug_entry *__hash_bucket_find(struct hash_bucket *bucket,
						  struct dma_debug_entry *ref,
						  match_fn match)
{
	struct dma_debug_entry *entry, *ret = NULL;
	int matches = 0, match_lvl, last_lvl = -1;

	list_for_each_entry(entry, &bucket->list, list) {
		if (!match(ref, entry))
			continue;
		matches += 1;
		match_lvl = 0;
		entry->size         == ref->size         ? ++match_lvl : 0;
		entry->type         == ref->type         ? ++match_lvl : 0;
		entry->direction    == ref->direction    ? ++match_lvl : 0;
		entry->sg_call_ents == ref->sg_call_ents ? ++match_lvl : 0;

		if (match_lvl == 4) {
			return entry;
		} else if (match_lvl > last_lvl) {
			last_lvl = match_lvl;
			ret      = entry;
		}
	}
	ret = (matches == 1) ? ret : NULL;

	return ret;
}

static struct dma_debug_entry *bucket_find_exact(struct hash_bucket *bucket,
						 struct dma_debug_entry *ref)
{
	return __hash_bucket_find(bucket, ref, exact_match);
}

static struct dma_debug_entry *bucket_find_contain(struct hash_bucket **bucket,
						   struct dma_debug_entry *ref,
						   unsigned long *flags)
{

	unsigned int max_range = dma_get_max_seg_size(ref->dev);
	struct dma_debug_entry *entry, index = *ref;
	unsigned int range = 0;

	while (range <= max_range) {
		entry = __hash_bucket_find(*bucket, ref, containing_match);

		if (entry)
			return entry;

		/*
		 * Nothing found, go back a hash bucket
		 */
		put_hash_bucket(*bucket, flags);
		range          += (1 << HASH_FN_SHIFT);
		index.dev_addr -= (1 << HASH_FN_SHIFT);
		*bucket = get_hash_bucket(&index, flags);
	}

	return NULL;
}
static void hash_bucket_add(struct hash_bucket *bucket,
			    struct dma_debug_entry *entry)
{
	list_add_tail(&entry->list, &bucket->list);
}
static void hash_bucket_del(struct dma_debug_entry *entry)
{
	list_del(&entry->list);
}

static unsigned long long phys_addr(struct dma_debug_entry *entry)
{
	if (entry->type == dma_debug_resource)
		return __pfn_to_phys(entry->pfn) + entry->offset;

	return page_to_phys(pfn_to_page(entry->pfn)) + entry->offset;
}

/*
 * entah.... gw juga gatau kapan kelarnya buat kernel hahhahahahihihihihi
 */
void debug_dma_dump_mappings(struct device *dev)
{
	int idx;

	for (idx = 0; idx < HASH_SIZE; idx++) {
		struct hash_bucket *bucket = &dma_entry_hash[idx];
		struct dma_debug_entry *entry;
		unsigned long flags;

		spin_lock_irqsave(&bucket->lock, flags);

		list_for_each_entry(entry, &bucket->list, list) {
			if (!dev || dev == entry->dev) {
				dev_info(entry->dev,
					 "%s idx %d P=%Lx N=%lx D=%Lx L=%Lx %s %s\n",
					 type2name[entry->type], idx,
					 phys_addr(entry), entry->pfn,
					 entry->dev_addr, entry->size,
					 dir2name[entry->direction],
					 maperr2str[entry->map_err_type]);
			}
		}

		spin_unlock_irqrestore(&bucket->lock, flags);
	}
}
static RADIX_TREE(dma_active_cacheline, GFP_NOWAIT);
static DEFINE_SPINLOCK(radix_lock);
#define ACTIVE_CACHELINE_MAX_OVERLAP ((1 << RADIX_TREE_MAX_TAGS) - 1)
#define CACHELINE_PER_PAGE_SHIFT (PAGE_SHIFT - L1_CACHE_SHIFT)
#define CACHELINES_PER_PAGE (1 << CACHELINE_PER_PAGE_SHIFT)

static phys_addr_t to_cacheline_number(struct dma_debug_entry *entry)
{
	return (entry->pfn << CACHELINE_PER_PAGE_SHIFT) +
		(entry->offset >> L1_CACHE_SHIFT);
}

static int active_cacheline_read_overlap(phys_addr_t cln)
{
	int overlap = 0, i;

	for (i = RADIX_TREE_MAX_TAGS - 1; i >= 0; i--)
		if (radix_tree_tag_get(&dma_active_cacheline, cln, i))
			overlap |= 1 << i;
	return overlap;
}

static int active_cacheline_set_overlap(phys_addr_t cln, int overlap)
{
	int i;

	if (overlap > ACTIVE_CACHELINE_MAX_OVERLAP || overlap < 0)
		return overlap;

	for (i = RADIX_TREE_MAX_TAGS - 1; i >= 0; i--)
		if (overlap & 1 << i)
			radix_tree_tag_set(&dma_active_cacheline, cln, i);
		else
			radix_tree_tag_clear(&dma_active_cacheline, cln, i);

	return overlap;
}

static void active_cacheline_inc_overlap(phys_addr_t cln)
{
	int overlap = active_cacheline_read_overlap(cln);

	overlap = active_cacheline_set_overlap(cln, ++overlap);
	WARN_ONCE(overlap > ACTIVE_CACHELINE_MAX_OVERLAP,
		  "DMA-API: exceeded %d overlapping mappings of cacheline %pa\n",
		  ACTIVE_CACHELINE_MAX_OVERLAP, &cln);
}

static int active_cacheline_dec_overlap(phys_addr_t cln)
{
	int overlap = active_cacheline_read_overlap(cln);

	return active_cacheline_set_overlap(cln, --overlap);
}

static int active_cacheline_insert(struct dma_debug_entry *entry)
{
	phys_addr_t cln = to_cacheline_number(entry);
	unsigned long flags;
	int rc;
	if (entry->direction == DMA_TO_DEVICE)
		return 0;

	spin_lock_irqsave(&radix_lock, flags);
	rc = radix_tree_insert(&dma_active_cacheline, cln, entry);
	if (rc == -EEXIST)
		active_cacheline_inc_overlap(cln);
	spin_unlock_irqrestore(&radix_lock, flags);

	return rc;
}

static void active_cacheline_remove(struct dma_debug_entry *entry)
{
	phys_addr_t cln = to_cacheline_number(entry);
	unsigned long flags;

	/* ...mirror the insert case */
	if (entry->direction == DMA_TO_DEVICE)
		return;

	spin_lock_irqsave(&radix_lock, flags);
	if (active_cacheline_dec_overlap(cln) < 0)
		radix_tree_delete(&dma_active_cacheline, cln);
	spin_unlock_irqrestore(&radix_lock, flags);
}
void debug_dma_assert_idle(struct page *page)
{
	static struct dma_debug_entry *ents[CACHELINES_PER_PAGE];
	struct dma_debug_entry *entry = NULL;
	void **results = (void **) &ents;
	unsigned int nents, i;
	unsigned long flags;
	phys_addr_t cln;

	if (dma_debug_disabled())
		return;

	if (!page)
		return;

	cln = (phys_addr_t) page_to_pfn(page) << CACHELINE_PER_PAGE_SHIFT;
	spin_lock_irqsave(&radix_lock, flags);
	nents = radix_tree_gang_lookup(&dma_active_cacheline, results, cln,
				       CACHELINES_PER_PAGE);
	for (i = 0; i < nents; i++) {
		phys_addr_t ent_cln = to_cacheline_number(ents[i]);

		if (ent_cln == cln) {
			entry = ents[i];
			break;
		} else if (ent_cln >= cln + CACHELINES_PER_PAGE)
			break;
	}
	spin_unlock_irqrestore(&radix_lock, flags);

	if (!entry)
		return;

	cln = to_cacheline_number(entry);
	err_printk(entry->dev, entry,
		   "DMA-API: cpu touching an active dma mapped cacheline [cln=%pa]\n",
		   &cln);
}

static void add_dma_entry(struct dma_debug_entry *entry)
{
	struct hash_bucket *bucket;
	unsigned long flags;
	int rc;

	bucket = get_hash_bucket(entry, &flags);
	hash_bucket_add(bucket, entry);
	put_hash_bucket(bucket, &flags);

	rc = active_cacheline_insert(entry);
	if (rc == -ENOMEM) {
		pr_err("DMA-API: cacheline tracking ENOMEM, dma-debug disabled\n");
		global_disable = true;
	}
}

static struct dma_debug_entry *__dma_entry_alloc(void)
{
	struct dma_debug_entry *entry;

	entry = list_entry(free_entries.next, struct dma_debug_entry, list);
	list_del(&entry->list);
	memset(entry, 0, sizeof(*entry));

	num_free_entries -= 1;
	if (num_free_entries < min_free_entries)
		min_free_entries = num_free_entries;

	return entry;
}
static struct dma_debug_entry *dma_entry_alloc(void)
{
	struct dma_debug_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&free_entries_lock, flags);

	if (list_empty(&free_entries)) {
		global_disable = true;
		spin_unlock_irqrestore(&free_entries_lock, flags);
		pr_err("DMA-API: debugging out of memory - disabling\n");
		return NULL;
	}

	entry = __dma_entry_alloc();

	spin_unlock_irqrestore(&free_entries_lock, flags);

#ifdef CONFIG_STACKTRACE
	entry->stacktrace.max_entries = DMA_DEBUG_STACKTRACE_ENTRIES;
	entry->stacktrace.entries = entry->st_entries;
	entry->stacktrace.skip = 2;
	save_stack_trace(&entry->stacktrace);
#endif

	return entry;
}

static void dma_entry_free(struct dma_debug_entry *entry)
{
	unsigned long flags;

	active_cacheline_remove(entry);
	spin_lock_irqsave(&free_entries_lock, flags);
	list_add(&entry->list, &free_entries);
	num_free_entries += 1;
	spin_unlock_irqrestore(&free_entries_lock, flags);
}

int dma_debug_resize_entries(u32 num_entries)
{
	int i, delta, ret = 0;
	unsigned long flags;
	struct dma_debug_entry *entry;
	LIST_HEAD(tmp);

	spin_lock_irqsave(&free_entries_lock, flags);

	if (nr_total_entries < num_entries) {
		delta = num_entries - nr_total_entries;

		spin_unlock_irqrestore(&free_entries_lock, flags);

		for (i = 0; i < delta; i++) {
			entry = kzalloc(sizeof(*entry), GFP_KERNEL);
			if (!entry)
				break;

			list_add_tail(&entry->list, &tmp);
		}

		spin_lock_irqsave(&free_entries_lock, flags);

		list_splice(&tmp, &free_entries);
		nr_total_entries += i;
		num_free_entries += i;
	} else {
		delta = nr_total_entries - num_entries;

		for (i = 0; i < delta && !list_empty(&free_entries); i++) {
			entry = __dma_entry_alloc();
			kfree(entry);
		}

		nr_total_entries -= i;
	}

	if (nr_total_entries != num_entries)
		ret = 1;

	spin_unlock_irqrestore(&free_entries_lock, flags);

	return ret;
}

static int prealloc_memory(u32 num_entries)
{
	struct dma_debug_entry *entry, *next_entry;
	int i;

	for (i = 0; i < num_entries; ++i) {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			goto out_err;

		list_add_tail(&entry->list, &free_entries);
	}

	num_free_entries = num_entries;
	min_free_entries = num_entries;

	pr_info("DMA-API: preallocated %d debug entries\n", num_entries);

	return 0;

out_err:

	list_for_each_entry_safe(entry, next_entry, &free_entries, list) {
		list_del(&entry->list);
		kfree(entry);
	}

	return -ENOMEM;
}

static ssize_t filter_read(struct file *file, char __user *user_buf,
			   size_t count, loff_t *ppos)
{
	char buf[NAME_MAX_LEN + 1];
	unsigned long flags;
	int len;

	if (!current_driver_name[0])
		return 0;
	read_lock_irqsave(&driver_name_lock, flags);
	len = scnprintf(buf, NAME_MAX_LEN + 1, "%s\n", current_driver_name);
	read_unlock_irqrestore(&driver_name_lock, flags);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t filter_write(struct file *file, const char __user *userbuf,
			    size_t count, loff_t *ppos)
{
	char buf[NAME_MAX_LEN];
	unsigned long flags;
	size_t len;
	int i;
	len = min(count, (size_t)(NAME_MAX_LEN - 1));
	if (copy_from_user(buf, userbuf, len))
		return -EFAULT;

	buf[len] = 0;

	write_lock_irqsave(&driver_name_lock, flags);
	if (!isalnum(buf[0])) {
	
		if (current_driver_name[0])
			pr_info("DMA-API: switching off dma-debug driver filter\n");
		current_driver_name[0] = 0;
		current_driver = NULL;
		goto out_unlock;
	}
	for (i = 0; i < NAME_MAX_LEN - 1; ++i) {
		current_driver_name[i] = buf[i];
		if (isspace(buf[i]) || buf[i] == ' ' || buf[i] == 0)
			break;
	}
	current_driver_name[i] = 0;
	current_driver = NULL;

	pr_info("DMA-API: enable driver filter for driver [%s]\n",
		current_driver_name);

out_unlock:
	write_unlock_irqrestore(&driver_name_lock, flags);

	return count;
}

static const struct file_operations filter_fops = {
	.read  = filter_read,
	.write = filter_write,
	.llseek = default_llseek,
};

static int dma_debug_fs_init(void)
{
	dma_debug_dent = debugfs_create_dir("dma-api", NULL);
	if (!dma_debug_dent) {
		pr_err("DMA-API: can not create debugfs directory\n");
		return -ENOMEM;
	}

	global_disable_dent = debugfs_create_bool("disabled", 0444,
			dma_debug_dent,
			&global_disable);
	if (!global_disable_dent)
		goto out_err;

	error_count_dent = debugfs_create_u32("error_count", 0444,
			dma_debug_dent, &error_count);
	if (!error_count_dent)
		goto out_err;

	show_all_errors_dent = debugfs_create_u32("all_errors", 0644,
			dma_debug_dent,
			&show_all_errors);
	if (!show_all_errors_dent)
		goto out_err;

	show_num_errors_dent = debugfs_create_u32("num_errors", 0644,
			dma_debug_dent,
			&show_num_errors);
	if (!show_num_errors_dent)
		goto out_err;

	num_free_entries_dent = debugfs_create_u32("num_free_entries", 0444,
			dma_debug_dent,
			&num_free_entries);
	if (!num_free_entries_dent)
		goto out_err;

	min_free_entries_dent = debugfs_create_u32("min_free_entries", 0444,
			dma_debug_dent,
			&min_free_entries);
	if (!min_free_entries_dent)
		goto out_err;

	filter_dent = debugfs_create_file("driver_filter", 0644,
					  dma_debug_dent, NULL, &filter_fops);
	if (!filter_dent)
		goto out_err;

	return 0;

out_err:
	debugfs_remove_recursive(dma_debug_dent);

	return -ENOMEM;
}

static int device_dma_allocations(struct device *dev, struct dma_debug_entry **out_entry)
{
	struct dma_debug_entry *entry;
	unsigned long flags;
	int count = 0, i;

	for (i = 0; i < HASH_SIZE; ++i) {
		spin_lock_irqsave(&dma_entry_hash[i].lock, flags);
		list_for_each_entry(entry, &dma_entry_hash[i].list, list) {
			if (entry->dev == dev) {
				count += 1;
				*out_entry = entry;
			}
		}
		spin_unlock_irqrestore(&dma_entry_hash[i].lock, flags);
	}

	return count;
}

static int dma_debug_device_change(struct notifier_block *nb, unsigned long action, void *data)
{
	struct device *dev = data;
	struct dma_debug_entry *uninitialized_var(entry);
	int count;

	if (dma_debug_disabled())
		return 0;

	switch (action) {
	case BUS_NOTIFY_UNBOUND_DRIVER:
		count = device_dma_allocations(dev, &entry);
		if (count == 0)
			break;
		err_printk(dev, entry, "DMA-API: device driver has pending "
				"DMA allocations while released from device "
				"[count=%d]\n"
				"One of leaked entries details: "
				"[device address=0x%016llx] [size=%llu bytes] "
				"[mapped with %s] [mapped as %s]\n",
			count, entry->dev_addr, entry->size,
			dir2name[entry->direction], type2name[entry->type]);
		break;
	default:
		break;
	}

	return 0;
}

void dma_debug_add_bus(struct bus_type *bus)
{
	struct notifier_block *nb;

	if (dma_debug_disabled())
		return;

	nb = kzalloc(sizeof(struct notifier_block), GFP_KERNEL);
	if (nb == NULL) {
		pr_err("dma_debug_add_bus: out of memory\n");
		return;
	}

	nb->notifier_call = dma_debug_device_change;

	bus_register_notifier(bus, nb);
}

static int dma_debug_init(void)
{
	int i;
	if (global_disable)
		return 0;

	for (i = 0; i < HASH_SIZE; ++i) {
		INIT_LIST_HEAD(&dma_entry_hash[i].list);
		spin_lock_init(&dma_entry_hash[i].lock);
	}

	if (dma_debug_fs_init() != 0) {
		pr_err("DMA-API: error creating debugfs entries - disabling\n");
		global_disable = true;

		return 0;
	}

	if (prealloc_memory(nr_prealloc_entries) != 0) {
		pr_err("DMA-API: debugging out of memory error - disabled\n");
		global_disable = true;

		return 0;
	}

	nr_total_entries = num_free_entries;

	dma_debug_initialized = true;

	pr_info("DMA-API: debugging enabled by kernel config\n");
	return 0;
}
core_initcall(dma_debug_init);

static __init int dma_debug_cmdline(char *str)
{
	if (!str)
		return -EINVAL;

	if (strncmp(str, "off", 3) == 0) {
		pr_info("DMA-API: debugging disabled on kernel command line\n");
		global_disable = true;
	}

	return 0;
}

static __init int dma_debug_entries_cmdline(char *str)
{
	if (!str)
		return -EINVAL;
	if (!get_option(&str, &nr_prealloc_entries))
		nr_prealloc_entries = PREALLOC_DMA_DEBUG_ENTRIES;
	return 0;
}

__setup("dma_debug=", dma_debug_cmdline);
__setup("dma_debug_entries=", dma_debug_entries_cmdline);

static void check_unmap(struct dma_debug_entry *ref)
{
	struct dma_debug_entry *entry;
	struct hash_bucket *bucket;
	unsigned long flags;

	bucket = get_hash_bucket(ref, &flags);
	entry = bucket_find_exact(bucket, ref);

	if (!entry) {
		put_hash_bucket(bucket, &flags);

		if (dma_mapping_error(ref->dev, ref->dev_addr)) {
			err_printk(ref->dev, NULL,
				   "DMA-API: device driver tries to free an "
				   "invalid DMA memory address\n");
		} else {
			err_printk(ref->dev, NULL,
				   "DMA-API: device driver tries to free DMA "
				   "memory it has not allocated [device "
				   "address=0x%016llx] [size=%llu bytes]\n",
				   ref->dev_addr, ref->size);
		}
		return;
	}

	if (ref->size != entry->size) {
		err_printk(ref->dev, entry, "DMA-API: device driver frees "
			   "DMA memory with different size "
			   "[device address=0x%016llx] [map size=%llu bytes] "
			   "[unmap size=%llu bytes]\n",
			   ref->dev_addr, entry->size, ref->size);
	}

	if (ref->type != entry->type) {
		err_printk(ref->dev, entry, "DMA-API: device driver frees "
			   "DMA memory with wrong function "
			   "[device address=0x%016llx] [size=%llu bytes] "
			   "[mapped as %s] [unmapped as %s]\n",
			   ref->dev_addr, ref->size,
			   type2name[entry->type], type2name[ref->type]);
	} else if ((entry->type == dma_debug_coherent) &&
		   (phys_addr(ref) != phys_addr(entry))) {
		err_printk(ref->dev, entry, "DMA-API: device driver frees "
			   "DMA memory with different CPU address "
			   "[device address=0x%016llx] [size=%llu bytes] "
			   "[cpu alloc address=0x%016llx] "
			   "[cpu free address=0x%016llx]",
			   ref->dev_addr, ref->size,
			   phys_addr(entry),
			   phys_addr(ref));
	}

	if (ref->sg_call_ents && ref->type == dma_debug_sg &&
	    ref->sg_call_ents != entry->sg_call_ents) {
		err_printk(ref->dev, entry, "DMA-API: device driver frees "
			   "DMA sg list with different entry count "
			   "[map count=%d] [unmap count=%d]\n",
			   entry->sg_call_ents, ref->sg_call_ents);
	}
	if (ref->direction != entry->direction) {
		err_printk(ref->dev, entry, "DMA-API: device driver frees "
			   "DMA memory with different direction "
			   "[device address=0x%016llx] [size=%llu bytes] "
			   "[mapped with %s] [unmapped with %s]\n",
			   ref->dev_addr, ref->size,
			   dir2name[entry->direction],
			   dir2name[ref->direction]);
	}
	if (entry->map_err_type == MAP_ERR_NOT_CHECKED) {
		err_printk(ref->dev, entry,
			   "DMA-API: device driver failed to check map error"
			   "[device address=0x%016llx] [size=%llu bytes] "
			   "[mapped as %s]",
			   ref->dev_addr, ref->size,
			   type2name[entry->type]);
	}

	hash_bucket_del(entry);
	dma_entry_free(entry);

	put_hash_bucket(bucket, &flags);
}

static void check_for_stack(struct device *dev,
			    struct page *page, size_t offset)
{
	void *addr;
	struct vm_struct *stack_vm_area = task_stack_vm_area(current);

	if (!stack_vm_area) {
		if (PageHighMem(page))
			return;
		addr = page_address(page) + offset;
		if (object_is_on_stack(addr))
			err_printk(dev, NULL, "DMA-API: device driver maps memory from stack [addr=%p]\n", addr);
	} else {
		int i;

		for (i = 0; i < stack_vm_area->nr_pages; i++) {
			if (page != stack_vm_area->pages[i])
				continue;

			addr = (u8 *)current->stack + i * PAGE_SIZE + offset;
			err_printk(dev, NULL, "DMA-API: device driver maps memory from stack [probable addr=%p]\n", addr);
			break;
		}
	}
}

static inline bool overlap(void *addr, unsigned long len, void *start, void *end)
{
	unsigned long a1 = (unsigned long)addr;
	unsigned long b1 = a1 + len;
	unsigned long a2 = (unsigned long)start;
	unsigned long b2 = (unsigned long)end;

	return !(b1 <= a2 || a1 >= b2);
}

static void check_for_illegal_area(struct device *dev, void *addr, unsigned long len)
{
	if (overlap(addr, len, _stext, _etext) ||
	    overlap(addr, len, __start_rodata, __end_rodata))
		err_printk(dev, NULL, "DMA-API: device driver maps memory from kernel text or rodata [addr=%p] [len=%lu]\n", addr, len);
}

static void check_sync(struct device *dev,
		       struct dma_debug_entry *ref,
		       bool to_cpu)
{
	struct dma_debug_entry *entry;
	struct hash_bucket *bucket;
	unsigned long flags;

	bucket = get_hash_bucket(ref, &flags);

	entry = bucket_find_contain(&bucket, ref, &flags);

	if (!entry) {
		err_printk(dev, NULL, "DMA-API: device driver tries "
				"to sync DMA memory it has not allocated "
				"[device address=0x%016llx] [size=%llu bytes]\n",
				(unsigned long long)ref->dev_addr, ref->size);
		goto out;
	}

	if (ref->size > entry->size) {
		err_printk(dev, entry, "DMA-API: device driver syncs"
				" DMA memory outside allocated range "
				"[device address=0x%016llx] "
				"[allocation size=%llu bytes] "
				"[sync offset+size=%llu]\n",
				entry->dev_addr, entry->size,
				ref->size);
	}

	if (entry->direction == DMA_BIDIRECTIONAL)
		goto out;

	if (ref->direction != entry->direction) {
		err_printk(dev, entry, "DMA-API: device driver syncs "
				"DMA memory with different direction "
				"[device address=0x%016llx] [size=%llu bytes] "
				"[mapped with %s] [synced with %s]\n",
				(unsigned long long)ref->dev_addr, entry->size,
				dir2name[entry->direction],
				dir2name[ref->direction]);
	}
if (to_cpu && !(entry->direction == DMA_FROM_DEVICE) &&
		      !(ref->direction == DMA_TO_DEVICE))
		err_printk(dev, entry, "DMA-API: device driver syncs "
				"device read-only DMA memory for cpu "
				"[device address=0x%016llx] [size=%llu bytes] "
				"[mapped with %s] [synced with %s]\n",
				(unsigned long long)ref->dev_addr, entry->size,
				dir2name[entry->direction],
				dir2name[ref->direction]);

	if (!to_cpu && !(entry->direction == DMA_TO_DEVICE) &&
		       !(ref->direction == DMA_FROM_DEVICE))
		err_printk(dev, entry, "DMA-API: device driver syncs "
				"device write-only DMA memory to device "
				"[device address=0x%016llx] [size=%llu bytes] "
				"[mapped with %s] [synced with %s]\n",
				(unsigned long long)ref->dev_addr, entry->size,
				dir2name[entry->direction],
				dir2name[ref->direction]);

	if (ref->sg_call_ents && ref->type == dma_debug_sg &&
	    ref->sg_call_ents != entry->sg_call_ents) {
		err_printk(ref->dev, entry, "DMA-API: device driver syncs "
			   "DMA sg list with different entry count "
			   "[map count=%d] [sync count=%d]\n",
			   entry->sg_call_ents, ref->sg_call_ents);
	}

out:
	put_hash_bucket(bucket, &flags);
}

static void check_sg_segment(struct device *dev, struct scatterlist *sg)
{
#ifdef CONFIG_DMA_API_DEBUG_SG
	unsigned int max_seg = dma_get_max_seg_size(dev);
	u64 start, end, boundary = dma_get_seg_boundary(dev);
	if (sg->length > max_seg)
		err_printk(dev, NULL, "DMA-API: mapping sg segment longer than device claims to support [len=%u] [max=%u]\n",
			   sg->length, max_seg);
	start = sg_dma_address(sg);
	end = start + sg_dma_len(sg) - 1;
	if ((start ^ end) & ~boundary)
		err_printk(dev, NULL, "DMA-API: mapping sg segment across boundary [start=0x%016llx] [end=0x%016llx] [boundary=0x%016llx]\n",
			   start, end, boundary);
#endif
}

void debug_dma_map_single(struct device *dev, const void *addr,
			    unsigned long len)
{
	if (unlikely(dma_debug_disabled()))
		return;

	if (!virt_addr_valid(addr))
		err_printk(dev, NULL, "DMA-API: device driver maps memory from invalid area [addr=%p] [len=%lu]\n",
			   addr, len);

	if (is_vmalloc_addr(addr))
		err_printk(dev, NULL, "DMA-API: device driver maps memory from vmalloc area [addr=%p] [len=%lu]\n",
			   addr, len);
}
EXPORT_SYMBOL(debug_dma_map_single);

void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
			size_t size, int direction, dma_addr_t dma_addr,
			bool map_single)
{
	struct dma_debug_entry *entry;

	if (unlikely(dma_debug_disabled()))
		return;

	if (dma_mapping_error(dev, dma_addr))
		return;

	entry = dma_entry_alloc();
	if (!entry)
		return;

	entry->dev       = dev;
	entry->type      = dma_debug_page;
	entry->pfn	 = page_to_pfn(page);
	entry->offset	 = offset,
	entry->dev_addr  = dma_addr;
	entry->size      = size;
	entry->direction = direction;
	entry->map_err_type = MAP_ERR_NOT_CHECKED;

	if (map_single)
		entry->type = dma_debug_single;

	check_for_stack(dev, page, offset);

	if (!PageHighMem(page)) {
		void *addr = page_address(page) + offset;

		check_for_illegal_area(dev, addr, size);
	}

	add_dma_entry(entry);
}
EXPORT_SYMBOL(debug_dma_map_page);

void debug_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	struct dma_debug_entry ref;
	struct dma_debug_entry *entry;
	struct hash_bucket *bucket;
	unsigned long flags;

	if (unlikely(dma_debug_disabled()))
		return;

	ref.dev = dev;
	ref.dev_addr = dma_addr;
	bucket = get_hash_bucket(&ref, &flags);

	list_for_each_entry(entry, &bucket->list, list) {
		if (!exact_match(&ref, entry))
			continue;
		if (entry->map_err_type == MAP_ERR_NOT_CHECKED) {
			entry->map_err_type = MAP_ERR_CHECKED;
			break;
		}
	}

	put_hash_bucket(bucket, &flags);
}
EXPORT_SYMBOL(debug_dma_mapping_error);

void debug_dma_unmap_page(struct device *dev, dma_addr_t addr,
			  size_t size, int direction, bool map_single)
{
	struct dma_debug_entry ref = {
		.type           = dma_debug_page,
		.dev            = dev,
		.dev_addr       = addr,
		.size           = size,
		.direction      = direction,
	};

	if (unlikely(dma_debug_disabled()))
		return;

	if (map_single)
		ref.type = dma_debug_single;

	check_unmap(&ref);
}
EXPORT_SYMBOL(debug_dma_unmap_page);

void debug_dma_map_sg(struct device *dev, struct scatterlist *sg,
		      int nents, int mapped_ents, int direction)
{
	struct dma_debug_entry *entry;
	struct scatterlist *s;
	int i;

	if (unlikely(dma_debug_disabled()))
		return;

	for_each_sg(sg, s, mapped_ents, i) {
		entry = dma_entry_alloc();
		if (!entry)
			return;

		entry->type           = dma_debug_sg;
		entry->dev            = dev;
		entry->pfn	      = page_to_pfn(sg_page(s));
		entry->offset	      = s->offset,
		entry->size           = sg_dma_len(s);
		entry->dev_addr       = sg_dma_address(s);
		entry->direction      = direction;
		entry->sg_call_ents   = nents;
		entry->sg_mapped_ents = mapped_ents;

		check_for_stack(dev, sg_page(s), s->offset);

		if (!PageHighMem(sg_page(s))) {
			check_for_illegal_area(dev, sg_virt(s), sg_dma_len(s));
		}

		check_sg_segment(dev, s);

		add_dma_entry(entry);
	}
}
EXPORT_SYMBOL(debug_dma_map_sg);

static int get_nr_mapped_entries(struct device *dev,
				 struct dma_debug_entry *ref)
{
	struct dma_debug_entry *entry;
	struct hash_bucket *bucket;
	unsigned long flags;
	int mapped_ents;

	bucket       = get_hash_bucket(ref, &flags);
	entry        = bucket_find_exact(bucket, ref);
	mapped_ents  = 0;

	if (entry)
		mapped_ents = entry->sg_mapped_ents;
	put_hash_bucket(bucket, &flags);

	return mapped_ents;
}

void debug_dma_unmap_sg(struct device *dev, struct scatterlist *sglist,
			int nelems, int dir)
{
	struct scatterlist *s;
	int mapped_ents = 0, i;

	if (unlikely(dma_debug_disabled()))
		return;

	for_each_sg(sglist, s, nelems, i) {

		struct dma_debug_entry ref = {
			.type           = dma_debug_sg,
			.dev            = dev,
			.pfn		= page_to_pfn(sg_page(s)),
			.offset		= s->offset,
			.dev_addr       = sg_dma_address(s),
			.size           = sg_dma_len(s),
			.direction      = dir,
			.sg_call_ents   = nelems,
		};

		if (mapped_ents && i >= mapped_ents)
			break;

		if (!i)
			mapped_ents = get_nr_mapped_entries(dev, &ref);

		check_unmap(&ref);
	}
}
EXPORT_SYMBOL(debug_dma_unmap_sg);

void debug_dma_alloc_coherent(struct device *dev, size_t size,
			      dma_addr_t dma_addr, void *virt)
{
	struct dma_debug_entry *entry;

	if (unlikely(dma_debug_disabled()))
		return;

	if (unlikely(virt == NULL))
		return;
	if (!is_vmalloc_addr(virt) && !virt_addr_valid(virt))
		return;

	entry = dma_entry_alloc();
	if (!entry)
		return;

	entry->type      = dma_debug_coherent;
	entry->dev       = dev;
	entry->offset	 = offset_in_page(virt);
	entry->size      = size;
	entry->dev_addr  = dma_addr;
	entry->direction = DMA_BIDIRECTIONAL;

	if (is_vmalloc_addr(virt))
		entry->pfn = vmalloc_to_pfn(virt);
	else
		entry->pfn = page_to_pfn(virt_to_page(virt));

	add_dma_entry(entry);
}
EXPORT_SYMBOL(debug_dma_alloc_coherent);

void debug_dma_free_coherent(struct device *dev, size_t size,
			 void *virt, dma_addr_t addr)
{
	struct dma_debug_entry ref = {
		.type           = dma_debug_coherent,
		.dev            = dev,
		.offset		= offset_in_page(virt),
		.dev_addr       = addr,
		.size           = size,
		.direction      = DMA_BIDIRECTIONAL,
	};
	if (!is_vmalloc_addr(virt) && !virt_addr_valid(virt))
		return;

	if (is_vmalloc_addr(virt))
		ref.pfn = vmalloc_to_pfn(virt);
	else
		ref.pfn = page_to_pfn(virt_to_page(virt));

	if (unlikely(dma_debug_disabled()))
		return;

	check_unmap(&ref);
}
EXPORT_SYMBOL(debug_dma_free_coherent);

void debug_dma_map_resource(struct device *dev, phys_addr_t addr, size_t size,
			    int direction, dma_addr_t dma_addr)
{
	struct dma_debug_entry *entry;

	if (unlikely(dma_debug_disabled()))
		return;

	entry = dma_entry_alloc();
	if (!entry)
		return;

	entry->type		= dma_debug_resource;
	entry->dev		= dev;
	entry->pfn		= PHYS_PFN(addr);
	entry->offset		= offset_in_page(addr);
	entry->size		= size;
	entry->dev_addr		= dma_addr;
	entry->direction	= direction;
	entry->map_err_type	= MAP_ERR_NOT_CHECKED;

	add_dma_entry(entry);
}
EXPORT_SYMBOL(debug_dma_map_resource);

void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
			      size_t size, int direction)
{
	struct dma_debug_entry ref = {
		.type           = dma_debug_resource,
		.dev            = dev,
		.dev_addr       = dma_addr,
		.size           = size,
		.direction      = direction,
	};

	if (unlikely(dma_debug_disabled()))
		return;

	check_unmap(&ref);
}
EXPORT_SYMBOL(debug_dma_unmap_resource);

void debug_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
				   size_t size, int direction)
{
	struct dma_debug_entry ref;

	if (unlikely(dma_debug_disabled()))
		return;

	ref.type         = dma_debug_single;
	ref.dev          = dev;
	ref.dev_addr     = dma_handle;
	ref.size         = size;
	ref.direction    = direction;
	ref.sg_call_ents = 0;

	check_sync(dev, &ref, true);
}
EXPORT_SYMBOL(debug_dma_sync_single_for_cpu);

void debug_dma_sync_single_for_device(struct device *dev,
				      dma_addr_t dma_handle, size_t size,
				      int direction)
{
	struct dma_debug_entry ref;

	if (unlikely(dma_debug_disabled()))
		return;

	ref.type         = dma_debug_single;
	ref.dev          = dev;
	ref.dev_addr     = dma_handle;
	ref.size         = size;
	ref.direction    = direction;
	ref.sg_call_ents = 0;

	check_sync(dev, &ref, false);
}
EXPORT_SYMBOL(debug_dma_sync_single_for_device);

void debug_dma_sync_single_range_for_cpu(struct device *dev,
					 dma_addr_t dma_handle,
					 unsigned long offset, size_t size,
					 int direction)
{
	struct dma_debug_entry ref;

	if (unlikely(dma_debug_disabled()))
		return;

	ref.type         = dma_debug_single;
	ref.dev          = dev;
	ref.dev_addr     = dma_handle;
	ref.size         = offset + size;
	ref.direction    = direction;
	ref.sg_call_ents = 0;

	check_sync(dev, &ref, true);
}
EXPORT_SYMBOL(debug_dma_sync_single_range_for_cpu);

void debug_dma_sync_single_range_for_device(struct device *dev,
					    dma_addr_t dma_handle,
					    unsigned long offset,
					    size_t size, int direction)
{
	struct dma_debug_entry ref;

	if (unlikely(dma_debug_disabled()))
		return;

	ref.type         = dma_debug_single;
	ref.dev          = dev;
	ref.dev_addr     = dma_handle;
	ref.size         = offset + size;
	ref.direction    = direction;
	ref.sg_call_ents = 0;

	check_sync(dev, &ref, false);
}
EXPORT_SYMBOL(debug_dma_sync_single_range_for_device);

void debug_dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg,
			       int nelems, int direction)
{
	struct scatterlist *s;
	int mapped_ents = 0, i;

	if (unlikely(dma_debug_disabled()))
		return;

	for_each_sg(sg, s, nelems, i) {

		struct dma_debug_entry ref = {
			.type           = dma_debug_sg,
			.dev            = dev,
			.pfn		= page_to_pfn(sg_page(s)),
			.offset		= s->offset,
			.dev_addr       = sg_dma_address(s),
			.size           = sg_dma_len(s),
			.direction      = direction,
			.sg_call_ents   = nelems,
		};

		if (!i)
			mapped_ents = get_nr_mapped_entries(dev, &ref);

		if (i >= mapped_ents)
			break;

		check_sync(dev, &ref, true);
	}
}
EXPORT_SYMBOL(debug_dma_sync_sg_for_cpu);

void debug_dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
				  int nelems, int direction)
{
	struct scatterlist *s;
	int mapped_ents = 0, i;

	if (unlikely(dma_debug_disabled()))
		return;

	for_each_sg(sg, s, nelems, i) {

		struct dma_debug_entry ref = {
			.type           = dma_debug_sg,
			.dev            = dev,
			.pfn		= page_to_pfn(sg_page(s)),
			.offset		= s->offset,
			.dev_addr       = sg_dma_address(s),
			.size           = sg_dma_len(s),
			.direction      = direction,
			.sg_call_ents   = nelems,
		};
		if (!i)
			mapped_ents = get_nr_mapped_entries(dev, &ref);

		if (i >= mapped_ents)
			break;

		check_sync(dev, &ref, false);
	}
}
EXPORT_SYMBOL(debug_dma_sync_sg_for_device);

static int __init dma_debug_driver_setup(char *str)
{
	int i;

	for (i = 0; i < NAME_MAX_LEN - 1; ++i, ++str) {
		current_driver_name[i] = *str;
		if (*str == 0)
			break;
	}

	if (current_driver_name[0])
		pr_info("DMA-API: enable driver filter for driver [%s]\n",
			current_driver_name);


	return 1;
}
__setup("dma_debug_driver=", dma_debug_driver_setup);
static inline bool force_dma_unencrypted(void)
{
	return sev_active();
}

static bool
check_addr(struct device *dev, dma_addr_t dma_addr, size_t size,
		const char *caller)
{
	if (unlikely(dev && !dma_capable(dev, dma_addr, size))) {
		if (!dev->dma_mask) {
			dev_err(dev,
				"%s: call on device without dma_mask\n",
				caller);
			return false;
		}

		if (*dev->dma_mask >= DMA_BIT_MASK(32) || dev->bus_dma_mask) {
			dev_err(dev,
				"%s: overflow %pad+%zu of device mask %llx bus mask %llx\n",
				caller, &dma_addr, size,
				*dev->dma_mask, dev->bus_dma_mask);
		}
		return false;
	}
	return true;
}

static inline dma_addr_t phys_to_dma_direct(struct device *dev,
		phys_addr_t phys)
{
	if (force_dma_unencrypted())
		return __phys_to_dma(dev, phys);
	return phys_to_dma(dev, phys);
}

u64 dma_direct_get_required_mask(struct device *dev)
{
	u64 max_dma = phys_to_dma_direct(dev, (max_pfn - 1) << PAGE_SHIFT);

	if (dev->bus_dma_mask && dev->bus_dma_mask < max_dma)
		max_dma = dev->bus_dma_mask;

	return (1ULL << (fls64(max_dma) - 1)) * 2 - 1;
}

static gfp_t __dma_direct_optimal_gfp_mask(struct device *dev, u64 dma_mask,
		u64 *phys_mask)
{
	if (dev->bus_dma_mask && dev->bus_dma_mask < dma_mask)
		dma_mask = dev->bus_dma_mask;

	if (force_dma_unencrypted())
		*phys_mask = __dma_to_phys(dev, dma_mask);
	else
		*phys_mask = dma_to_phys(dev, dma_mask);
	if (*phys_mask <= DMA_BIT_MASK(ARCH_ZONE_DMA_BITS))
		return GFP_DMA;
	if (*phys_mask <= DMA_BIT_MASK(32))
		return GFP_DMA32;
	return 0;
}

static bool dma_coherent_ok(struct device *dev, phys_addr_t phys, size_t size)
{
	return phys_to_dma_direct(dev, phys) + size - 1 <=
			min_not_zero(dev->coherent_dma_mask, dev->bus_dma_mask);
}

void *dma_direct_alloc_pages(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	int page_order = get_order(size);
	struct page *page = NULL;
	u64 phys_mask;
	void *ret;

	if (attrs & DMA_ATTR_NO_WARN)
		gfp |= __GFP_NOWARN;
	gfp &= ~__GFP_ZERO;
	gfp |= __dma_direct_optimal_gfp_mask(dev, dev->coherent_dma_mask,
			&phys_mask);
again:
	if (gfpflags_allow_blocking(gfp)) {
		page = dma_alloc_from_contiguous(dev, count, page_order,
						 gfp & __GFP_NOWARN);
		if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
			dma_release_from_contiguous(dev, page, count);
			page = NULL;
		}
	}
	if (!page)
		page = alloc_pages_node(dev_to_node(dev), gfp, page_order);

	if (page && !dma_coherent_ok(dev, page_to_phys(page), size)) {
		__free_pages(page, page_order);
		page = NULL;

		if (IS_ENABLED(CONFIG_ZONE_DMA32) &&
		    phys_mask < DMA_BIT_MASK(64) &&
		    !(gfp & (GFP_DMA32 | GFP_DMA))) {
			gfp |= GFP_DMA32;
			goto again;
		}

		if (IS_ENABLED(CONFIG_ZONE_DMA) &&
		    phys_mask < DMA_BIT_MASK(32) && !(gfp & GFP_DMA)) {
			gfp = (gfp & ~GFP_DMA32) | GFP_DMA;
			goto again;
		}
	}

	if (!page)
		return NULL;
	ret = page_address(page);
	if (force_dma_unencrypted()) {
		set_memory_decrypted((unsigned long)ret, 1 << page_order);
		*dma_handle = __phys_to_dma(dev, page_to_phys(page));
	} else {
		*dma_handle = phys_to_dma(dev, page_to_phys(page));
	}
	memset(ret, 0, size);
	return ret;
}
void dma_direct_free_pages(struct device *dev, size_t size, void *cpu_addr,
		dma_addr_t dma_addr, unsigned long attrs)
{
	unsigned int count = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned int page_order = get_order(size);

	if (force_dma_unencrypted())
		set_memory_encrypted((unsigned long)cpu_addr, 1 << page_order);
	if (!dma_release_from_contiguous(dev, virt_to_page(cpu_addr), count))
		free_pages((unsigned long)cpu_addr, page_order);
}

void *dma_direct_alloc(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp, unsigned long attrs)
{
	if (!dev_is_dma_coherent(dev))
		return arch_dma_alloc(dev, size, dma_handle, gfp, attrs);
	return dma_direct_alloc_pages(dev, size, dma_handle, gfp, attrs);
}

void dma_direct_free(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_addr, unsigned long attrs)
{
	if (!dev_is_dma_coherent(dev))
		arch_dma_free(dev, size, cpu_addr, dma_addr, attrs);
	else
		dma_direct_free_pages(dev, size, cpu_addr, dma_addr, attrs);
}

static void dma_direct_sync_single_for_device(struct device *dev,
		dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
	if (dev_is_dma_coherent(dev))
		return;
	arch_sync_dma_for_device(dev, dma_to_phys(dev, addr), size, dir);
}

static void dma_direct_sync_sg_for_device(struct device *dev,
		struct scatterlist *sgl, int nents, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	if (dev_is_dma_coherent(dev))
		return;

	for_each_sg(sgl, sg, nents, i)
		arch_sync_dma_for_device(dev, sg_phys(sg), sg->length, dir);
}

#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
static void dma_direct_sync_single_for_cpu(struct device *dev,
		dma_addr_t addr, size_t size, enum dma_data_direction dir)
{
	if (dev_is_dma_coherent(dev))
		return;
	arch_sync_dma_for_cpu(dev, dma_to_phys(dev, addr), size, dir);
	arch_sync_dma_for_cpu_all(dev);
}

static void dma_direct_sync_sg_for_cpu(struct device *dev,
		struct scatterlist *sgl, int nents, enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	if (dev_is_dma_coherent(dev))
		return;

	for_each_sg(sgl, sg, nents, i)
		arch_sync_dma_for_cpu(dev, sg_phys(sg), sg->length, dir);
	arch_sync_dma_for_cpu_all(dev);
}

static void dma_direct_unmap_page(struct device *dev, dma_addr_t addr,
		size_t size, enum dma_data_direction dir, unsigned long attrs)
{
	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		dma_direct_sync_single_for_cpu(dev, addr, size, dir);
}

static void dma_direct_unmap_sg(struct device *dev, struct scatterlist *sgl,
		int nents, enum dma_data_direction dir, unsigned long attrs)
{
	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		dma_direct_sync_sg_for_cpu(dev, sgl, nents, dir);
}
#endif

dma_addr_t dma_direct_map_page(struct device *dev, struct page *page,
		unsigned long offset, size_t size, enum dma_data_direction dir,
		unsigned long attrs)
{
	phys_addr_t phys = page_to_phys(page) + offset;
	dma_addr_t dma_addr = phys_to_dma(dev, phys);

	if (!check_addr(dev, dma_addr, size, __func__))
		return DIRECT_MAPPING_ERROR;

	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		dma_direct_sync_single_for_device(dev, dma_addr, size, dir);
	return dma_addr;
}

int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
		enum dma_data_direction dir, unsigned long attrs)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, nents, i) {
		BUG_ON(!sg_page(sg));

		sg_dma_address(sg) = phys_to_dma(dev, sg_phys(sg));
		if (!check_addr(dev, sg_dma_address(sg), sg->length, __func__))
			return 0;
		sg_dma_len(sg) = sg->length;
	}

	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
		dma_direct_sync_sg_for_device(dev, sgl, nents, dir);
	return nents;
}
int dma_direct_supported(struct device *dev, u64 mask)
{
	u64 min_mask;

	if (IS_ENABLED(CONFIG_ZONE_DMA))
		min_mask = DMA_BIT_MASK(ARCH_ZONE_DMA_BITS);
	else
		min_mask = DMA_BIT_MASK(32);

	min_mask = min_t(u64, min_mask, (max_pfn - 1) << PAGE_SHIFT);

	return mask >= phys_to_dma(dev, min_mask);
}

int dma_direct_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	return dma_addr == DIRECT_MAPPING_ERROR;
}

const struct dma_map_ops dma_direct_ops = {
	.alloc			= dma_direct_alloc,
	.free			= dma_direct_free,
	.map_page		= dma_direct_map_page,
	.map_sg			= dma_direct_map_sg,
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE)
	.sync_single_for_device	= dma_direct_sync_single_for_device,
	.sync_sg_for_device	= dma_direct_sync_sg_for_device,
#endif
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
    defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
	.sync_single_for_cpu	= dma_direct_sync_single_for_cpu,
	.sync_sg_for_cpu	= dma_direct_sync_sg_for_cpu,
	.unmap_page		= dma_direct_unmap_page,
	.unmap_sg		= dma_direct_unmap_sg,
#endif
	.get_required_mask	= dma_direct_get_required_mask,
	.dma_supported		= dma_direct_supported,
	.mapping_error		= dma_direct_mapping_error,
	.cache_sync		= arch_dma_cache_sync,
};
EXPORT_SYMBOL(dma_direct_ops);
