DEFINE_MUTEX(klp_mutex);
#include "Screen.c"

static LIST_HEAD(klp_patches);

static struct kobject *klp_root_kobj;

static bool klp_is_module(struct klp_object *obj)
{
	return obj->name;
}

/* sets obj->mod if object is not vmlinux and module is found */
static void klp_find_object_module(struct klp_object *obj)
{
	struct module *mod;

	if (!klp_is_module(obj))
		return;

	mutex_lock(&module_mutex);
	/*
	 * We do not want to block removal of patched modules and therefore
	 * we do not take a reference here. The patches are removed by
	 * klp_module_going() instead.
	 */
	mod = find_module(obj->name);
	/*
	 * Do not mess work of klp_module_coming() and klp_module_going().
	 * Note that the patch might still be needed before klp_module_going()
	 * is called. Module functions can be called even in the GOING state
	 * until mod->exit() finishes. This is especially important for
	 * patches that modify semantic of the functions.
	 */
	if (mod && mod->klp_alive)
		obj->mod = mod;

	mutex_unlock(&module_mutex);
}

static bool klp_is_patch_registered(struct klp_patch *patch)
{
	struct klp_patch *mypatch;

	list_for_each_entry(mypatch, &klp_patches, list)
		if (mypatch == patch)
			return true;

	return false;
}

static bool klp_initialized(void)
{
	return !!klp_root_kobj;
}

struct klp_find_arg {
	const char *objname;
	const char *name;
	unsigned long addr;
	unsigned long count;
	unsigned long pos;
};

static int klp_find_callback(void *data, const char *name,
			     struct module *mod, unsigned long addr)
{
	struct klp_find_arg *args = data;

	if ((mod && !args->objname) || (!mod && args->objname))
		return 0;

	if (strcmp(args->name, name))
		return 0;

	if (args->objname && strcmp(args->objname, mod->name))
		return 0;

	args->addr = addr;
	args->count++;

	/*
	 * Finish the search when the symbol is found for the desired position
	 * or the position is not defined for a non-unique symbol.
	 */
	if ((args->pos && (args->count == args->pos)) ||
	    (!args->pos && (args->count > 1)))
		return 1;

	return 0;
}

static int klp_find_object_symbol(const char *objname, const char *name,
				  unsigned long sympos, unsigned long *addr)
{
	struct klp_find_arg args = {
		.objname = objname,
		.name = name,
		.addr = 0,
		.count = 0,
		.pos = sympos,
	};

	mutex_lock(&module_mutex);
	if (objname)
		module_kallsyms_on_each_symbol(klp_find_callback, &args);
	else
		kallsyms_on_each_symbol(klp_find_callback, &args);
	mutex_unlock(&module_mutex);

	/*
	 * Ensure an address was found. If sympos is 0, ensure symbol is unique;
	 * otherwise ensure the symbol position count matches sympos.
	 */
	if (args.addr == 0)
		pr_err("symbol '%s' not found in symbol table\n", name);
	else if (args.count > 1 && sympos == 0) {
		pr_err("unresolvable ambiguity for symbol '%s' in object '%s'\n",
		       name, objname);
	} else if (sympos != args.count && sympos > 0) {
		pr_err("symbol position %lu for symbol '%s' in object '%s' not found\n",
		       sympos, name, objname ? objname : "vmlinux");
	} else {
		*addr = args.addr;
		return 0;
	}

	*addr = 0;
	return -EINVAL;
}

static int klp_resolve_symbols(Elf_Shdr *relasec, struct module *pmod)
{
	int i, cnt, vmlinux, ret;
	char objname[MODULE_NAME_LEN];
	char symname[KSYM_NAME_LEN];
	char *strtab = pmod->core_kallsyms.strtab;
	Elf_Rela *relas;
	Elf_Sym *sym;
	unsigned long sympos, addr;

	/*
	 * Since the field widths for objname and symname in the sscanf()
	 * call are hard-coded and correspond to MODULE_NAME_LEN and
	 * KSYM_NAME_LEN respectively, we must make sure that MODULE_NAME_LEN
	 * and KSYM_NAME_LEN have the values we expect them to have.
	 *
	 * Because the value of MODULE_NAME_LEN can differ among architectures,
	 * we use the smallest/strictest upper bound possible (56, based on
	 * the current definition of MODULE_NAME_LEN) to prevent overflows.
	 */
	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 128);

	relas = (Elf_Rela *) relasec->sh_addr;
	/* For each rela in this klp relocation section */
	for (i = 0; i < relasec->sh_size / sizeof(Elf_Rela); i++) {
		sym = pmod->core_kallsyms.symtab + ELF_R_SYM(relas[i].r_info);
		if (sym->st_shndx != SHN_LIVEPATCH) {
			pr_err("symbol %s is not marked as a livepatch symbol\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		/* Format: .klp.sym.objname.symname,sympos */
		cnt = sscanf(strtab + sym->st_name,
			     ".klp.sym.%55[^.].%127[^,],%lu",
			     objname, symname, &sympos);
		if (cnt != 3) {
			pr_err("symbol %s has an incorrectly formatted name\n",
			       strtab + sym->st_name);
			return -EINVAL;
		}

		/* klp_find_object_symbol() treats a NULL objname as vmlinux */
		vmlinux = !strcmp(objname, "vmlinux");
		ret = klp_find_object_symbol(vmlinux ? NULL : objname,
					     symname, sympos, &addr);
		if (ret)
			return ret;

		sym->st_value = addr;
	}

	return 0;
}

static int klp_write_object_relocations(struct module *pmod,
					struct klp_object *obj)
{
	int i, cnt, ret = 0;
	const char *objname, *secname;
	char sec_objname[MODULE_NAME_LEN];
	Elf_Shdr *sec;

	if (WARN_ON(!klp_is_object_loaded(obj)))
		return -EINVAL;

	objname = klp_is_module(obj) ? obj->name : "vmlinux";

	/* For each klp relocation section */
	for (i = 1; i < pmod->klp_info->hdr.e_shnum; i++) {
		sec = pmod->klp_info->sechdrs + i;
		secname = pmod->klp_info->secstrings + sec->sh_name;
		if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
			continue;

		/*
		 * Format: .klp.rela.sec_objname.section_name
		 * See comment in klp_resolve_symbols() for an explanation
		 * of the selected field width value.
		 */
		cnt = sscanf(secname, ".klp.rela.%55[^.]", sec_objname);
		if (cnt != 1) {
			pr_err("section %s has an incorrectly formatted name\n",
			       secname);
			ret = -EINVAL;
			break;
		}

		if (strcmp(objname, sec_objname))
			continue;

		ret = klp_resolve_symbols(sec, pmod);
		if (ret)
			break;

		ret = apply_relocate_add(pmod->klp_info->sechdrs,
					 pmod->core_kallsyms.strtab,
					 pmod->klp_info->symndx, i, pmod);
		if (ret)
			break;
	}

	return ret;
}

static int __klp_disable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;

	if (WARN_ON(!patch->enabled))
		return -EINVAL;

	if (klp_transition_patch)
		return -EBUSY;

	/* enforce stacking: only the last enabled patch can be disabled */
	if (!list_is_last(&patch->list, &klp_patches) &&
	    list_next_entry(patch, list)->enabled)
		return -EBUSY;

	klp_init_transition(patch, KLP_UNPATCHED);

	klp_for_each_object(patch, obj)
		if (obj->patched)
			klp_pre_unpatch_callback(obj);

	/*
	 * Enforce the order of the func->transition writes in
	 * klp_init_transition() and the TIF_PATCH_PENDING writes in
	 * klp_start_transition().  In the rare case where klp_ftrace_handler()
	 * is called shortly after klp_update_patch_state() switches the task,
	 * this ensures the handler sees that func->transition is set.
	 */
	smp_wmb();

	klp_start_transition();
	klp_try_complete_transition();
	patch->enabled = false;

	return 0;
}

/**
 * klp_disable_patch() - disables a registered patch
 * @patch:	The registered, enabled patch to be disabled
 *
 * Unregisters the patched functions from ftrace.
 *
 * Return: 0 on success, otherwise error
 */
int klp_disable_patch(struct klp_patch *patch)
{
	int ret;

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto err;
	}

	if (!patch->enabled) {
		ret = -EINVAL;
		goto err;
	}

	ret = __klp_disable_patch(patch);

err:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_disable_patch);

static int __klp_enable_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	if (klp_transition_patch)
		return -EBUSY;

	if (WARN_ON(patch->enabled))
		return -EINVAL;

	/* enforce stacking: only the first disabled patch can be enabled */
	if (patch->list.prev != &klp_patches &&
	    !list_prev_entry(patch, list)->enabled)
		return -EBUSY;

	/*
	 * A reference is taken on the patch module to prevent it from being
	 * unloaded.
	 */
	if (!try_module_get(patch->mod))
		return -ENODEV;

	pr_notice("enabling patch '%s'\n", patch->mod->name);

	klp_init_transition(patch, KLP_PATCHED);

	/*
	 * Enforce the order of the func->transition writes in
	 * klp_init_transition() and the ops->func_stack writes in
	 * klp_patch_object(), so that klp_ftrace_handler() will see the
	 * func->transition updates before the handler is registered and the
	 * new funcs become visible to the handler.
	 */
	smp_wmb();

	klp_for_each_object(patch, obj) {
		if (!klp_is_object_loaded(obj))
			continue;

		ret = klp_pre_patch_callback(obj);
		if (ret) {
			pr_warn("pre-patch callback failed for object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto err;
		}

		ret = klp_patch_object(obj);
		if (ret) {
			pr_warn("failed to patch object '%s'\n",
				klp_is_module(obj) ? obj->name : "vmlinux");
			goto err;
		}
	}

	klp_start_transition();
	klp_try_complete_transition();
	patch->enabled = true;

	return 0;
err:
	pr_warn("failed to enable patch '%s'\n", patch->mod->name);

	klp_cancel_transition();
	return ret;
}

/**
 * klp_enable_patch() - enables a registered patch
 * @patch:	The registered, disabled patch to be enabled
 *
 * Performs the needed symbol lookups and code relocations,
 * then registers the patched functions with ftrace.
 *
 * Return: 0 on success, otherwise error
 */
int klp_enable_patch(struct klp_patch *patch)
{
	int ret;

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto err;
	}

	ret = __klp_enable_patch(patch);

err:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_enable_patch);

/*
 * Sysfs Interface
 *
 * /sys/kernel/livepatch
 * /sys/kernel/livepatch/<patch>
 * /sys/kernel/livepatch/<patch>/enabled
 * /sys/kernel/livepatch/<patch>/transition
 * /sys/kernel/livepatch/<patch>/signal
 * /sys/kernel/livepatch/<patch>/force
 * /sys/kernel/livepatch/<patch>/<object>
 * /sys/kernel/livepatch/<patch>/<object>/<function,sympos>
 */

static ssize_t enabled_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool enabled;

	ret = kstrtobool(buf, &enabled);
	if (ret)
		return ret;

	patch = container_of(kobj, struct klp_patch, kobj);

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		/*
		 * Module with the patch could either disappear meanwhile or is
		 * not properly initialized yet.
		 */
		ret = -EINVAL;
		goto err;
	}

	if (patch->enabled == enabled) {
		/* already in requested state */
		ret = -EINVAL;
		goto err;
	}

	if (patch == klp_transition_patch) {
		klp_reverse_transition();
	} else if (enabled) {
		ret = __klp_enable_patch(patch);
		if (ret)
			goto err;
	} else {
		ret = __klp_disable_patch(patch);
		if (ret)
			goto err;
	}

	mutex_unlock(&klp_mutex);

	return count;

err:
	mutex_unlock(&klp_mutex);
	return ret;
}

static ssize_t enabled_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	return snprintf(buf, PAGE_SIZE-1, "%d\n", patch->enabled);
}

static ssize_t transition_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	return snprintf(buf, PAGE_SIZE-1, "%d\n",
			patch == klp_transition_patch);
}

static ssize_t signal_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool val;

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (!val)
		return count;

	mutex_lock(&klp_mutex);

	patch = container_of(kobj, struct klp_patch, kobj);
	if (patch != klp_transition_patch) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	klp_send_signals();

	mutex_unlock(&klp_mutex);

	return count;
}

static ssize_t force_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct klp_patch *patch;
	int ret;
	bool val;

	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (!val)
		return count;

	mutex_lock(&klp_mutex);

	patch = container_of(kobj, struct klp_patch, kobj);
	if (patch != klp_transition_patch) {
		mutex_unlock(&klp_mutex);
		return -EINVAL;
	}

	klp_force_transition();

	mutex_unlock(&klp_mutex);

	return count;
}

static struct kobj_attribute enabled_kobj_attr = __ATTR_RW(enabled);
static struct kobj_attribute transition_kobj_attr = __ATTR_RO(transition);
static struct kobj_attribute signal_kobj_attr = __ATTR_WO(signal);
static struct kobj_attribute force_kobj_attr = __ATTR_WO(force);
static struct attribute *klp_patch_attrs[] = {
	&enabled_kobj_attr.attr,
	&transition_kobj_attr.attr,
	&signal_kobj_attr.attr,
	&force_kobj_attr.attr,
	NULL
};

static void klp_kobj_release_patch(struct kobject *kobj)
{
	struct klp_patch *patch;

	patch = container_of(kobj, struct klp_patch, kobj);
	complete(&patch->finish);
}

static struct kobj_type klp_ktype_patch = {
	.release = klp_kobj_release_patch,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_attrs = klp_patch_attrs,
};

static void klp_kobj_release_object(struct kobject *kobj)
{
}

static struct kobj_type klp_ktype_object = {
	.release = klp_kobj_release_object,
	.sysfs_ops = &kobj_sysfs_ops,
};

static void klp_kobj_release_func(struct kobject *kobj)
{
}

static struct kobj_type klp_ktype_func = {
	.release = klp_kobj_release_func,
	.sysfs_ops = &kobj_sysfs_ops,
};

/*
 * Free all functions' kobjects in the array up to some limit. When limit is
 * NULL, all kobjects are freed.
 */
static void klp_free_funcs_limited(struct klp_object *obj,
				   struct klp_func *limit)
{
	struct klp_func *func;

	for (func = obj->funcs; func->old_name && func != limit; func++)
		kobject_put(&func->kobj);
}

/* Clean up when a patched object is unloaded */
static void klp_free_object_loaded(struct klp_object *obj)
{
	struct klp_func *func;

	obj->mod = NULL;

	klp_for_each_func(obj, func)
		func->old_addr = 0;
}

/*
 * Free all objects' kobjects in the array up to some limit. When limit is
 * NULL, all kobjects are freed.
 */
static void klp_free_objects_limited(struct klp_patch *patch,
				     struct klp_object *limit)
{
	struct klp_object *obj;

	for (obj = patch->objs; obj->funcs && obj != limit; obj++) {
		klp_free_funcs_limited(obj, NULL);
		kobject_put(&obj->kobj);
	}
}

static void klp_free_patch(struct klp_patch *patch)
{
	klp_free_objects_limited(patch, NULL);
	if (!list_empty(&patch->list))
		list_del(&patch->list);
}

static int klp_init_func(struct klp_object *obj, struct klp_func *func)
{
	if (!func->old_name || !func->new_func)
		return -EINVAL;

	if (strlen(func->old_name) >= KSYM_NAME_LEN)
		return -EINVAL;

	INIT_LIST_HEAD(&func->stack_node);
	func->patched = false;
	func->transition = false;

	/* The format for the sysfs directory is <function,sympos> where sympos
	 * is the nth occurrence of this symbol in kallsyms for the patched
	 * object. If the user selects 0 for old_sympos, then 1 will be used
	 * since a unique symbol will be the first occurrence.
	 */
	return kobject_init_and_add(&func->kobj, &klp_ktype_func,
				    &obj->kobj, "%s,%lu", func->old_name,
				    func->old_sympos ? func->old_sympos : 1);
}

/* Arches may override this to finish any remaining arch-specific tasks */
void __weak arch_klp_init_object_loaded(struct klp_patch *patch,
					struct klp_object *obj)
{
}

/* parts of the initialization that is done only when the object is loaded */
static int klp_init_object_loaded(struct klp_patch *patch,
				  struct klp_object *obj)
{
	struct klp_func *func;
	int ret;

	module_disable_ro(patch->mod);
	ret = klp_write_object_relocations(patch->mod, obj);
	if (ret) {
		module_enable_ro(patch->mod, true);
		return ret;
	}

	arch_klp_init_object_loaded(patch, obj);
	module_enable_ro(patch->mod, true);

	klp_for_each_func(obj, func) {
		ret = klp_find_object_symbol(obj->name, func->old_name,
					     func->old_sympos,
					     &func->old_addr);
		if (ret)
			return ret;

		ret = kallsyms_lookup_size_offset(func->old_addr,
						  &func->old_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s'\n",
			       func->old_name);
			return -ENOENT;
		}

		ret = kallsyms_lookup_size_offset((unsigned long)func->new_func,
						  &func->new_size, NULL);
		if (!ret) {
			pr_err("kallsyms size lookup failed for '%s' replacement\n",
			       func->old_name);
			return -ENOENT;
		}
	}

	return 0;
}

static int klp_init_object(struct klp_patch *patch, struct klp_object *obj)
{
	struct klp_func *func;
	int ret;
	const char *name;

	if (!obj->funcs)
		return -EINVAL;

	if (klp_is_module(obj) && strlen(obj->name) >= MODULE_NAME_LEN)
		return -EINVAL;

	obj->patched = false;
	obj->mod = NULL;

	klp_find_object_module(obj);

	name = klp_is_module(obj) ? obj->name : "vmlinux";
	ret = kobject_init_and_add(&obj->kobj, &klp_ktype_object,
				   &patch->kobj, "%s", name);
	if (ret)
		return ret;

	klp_for_each_func(obj, func) {
		ret = klp_init_func(obj, func);
		if (ret)
			goto free;
	}

	if (klp_is_object_loaded(obj)) {
		ret = klp_init_object_loaded(patch, obj);
		if (ret)
			goto free;
	}

	return 0;

free:
	klp_free_funcs_limited(obj, func);
	kobject_put(&obj->kobj);
	return ret;
}

static int klp_init_patch(struct klp_patch *patch)
{
	struct klp_object *obj;
	int ret;

	if (!patch->objs)
		return -EINVAL;

	mutex_lock(&klp_mutex);

	patch->enabled = false;
	init_completion(&patch->finish);

	ret = kobject_init_and_add(&patch->kobj, &klp_ktype_patch,
				   klp_root_kobj, "%s", patch->mod->name);
	if (ret) {
		mutex_unlock(&klp_mutex);
		return ret;
	}

	klp_for_each_object(patch, obj) {
		ret = klp_init_object(patch, obj);
		if (ret)
			goto free;
	}

	list_add_tail(&patch->list, &klp_patches);

	mutex_unlock(&klp_mutex);

	return 0;

free:
	klp_free_objects_limited(patch, obj);

	mutex_unlock(&klp_mutex);

	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	return ret;
}

/**
 * klp_unregister_patch() - unregisters a patch
 * @patch:	Disabled patch to be unregistered
 *
 * Frees the data structures and removes the sysfs interface.
 *
 * Return: 0 on success, otherwise error
 */
int klp_unregister_patch(struct klp_patch *patch)
{
	int ret;

	mutex_lock(&klp_mutex);

	if (!klp_is_patch_registered(patch)) {
		ret = -EINVAL;
		goto err;
	}

	if (patch->enabled) {
		ret = -EBUSY;
		goto err;
	}

	klp_free_patch(patch);

	mutex_unlock(&klp_mutex);

	kobject_put(&patch->kobj);
	wait_for_completion(&patch->finish);

	return 0;
err:
	mutex_unlock(&klp_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(klp_unregister_patch);

/**
 * klp_register_patch() - registers a patch
 * @patch:	Patch to be registered
 *
 * Initializes the data structure associated with the patch and
 * creates the sysfs interface.
 *
 * There is no need to take the reference on the patch module here. It is done
 * later when the patch is enabled.
 *
 * Return: 0 on success, otherwise error
 */
int klp_register_patch(struct klp_patch *patch)
{
	if (!patch || !patch->mod)
		return -EINVAL;

	if (!is_livepatch_module(patch->mod)) {
		pr_err("module %s is not marked as a livepatch module\n",
		       patch->mod->name);
		return -EINVAL;
	}

	if (!klp_initialized())
		return -ENODEV;

	if (!klp_have_reliable_stack()) {
		pr_err("This architecture doesn't have support for the livepatch consistency model.\n");
		return -ENOSYS;
	}

	return klp_init_patch(patch);
}
EXPORT_SYMBOL_GPL(klp_register_patch);

/*
 * Remove parts of patches that touch a given kernel module. The list of
 * patches processed might be limited. When limit is NULL, all patches
 * will be handled.
 */
static void klp_cleanup_module_patches_limited(struct module *mod,
					       struct klp_patch *limit)
{
	struct klp_patch *patch;
	struct klp_object *obj;

	list_for_each_entry(patch, &klp_patches, list) {
		if (patch == limit)
			break;

		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			/*
			 * Only unpatch the module if the patch is enabled or
			 * is in transition.
			 */
			if (patch->enabled || patch == klp_transition_patch) {

				if (patch != klp_transition_patch)
					klp_pre_unpatch_callback(obj);

				pr_notice("reverting patch '%s' on unloading module '%s'\n",
					  patch->mod->name, obj->mod->name);
				klp_unpatch_object(obj);

				klp_post_unpatch_callback(obj);
			}

			klp_free_object_loaded(obj);
			break;
		}
	}
}

int klp_module_coming(struct module *mod)
{
	int ret;
	struct klp_patch *patch;
	struct klp_object *obj;

	if (WARN_ON(mod->state != MODULE_STATE_COMING))
		return -EINVAL;

	mutex_lock(&klp_mutex);
	/*
	 * Each module has to know that klp_module_coming()
	 * has been called. We never know what module will
	 * get patched by a new patch.
	 */
	mod->klp_alive = true;

	list_for_each_entry(patch, &klp_patches, list) {
		klp_for_each_object(patch, obj) {
			if (!klp_is_module(obj) || strcmp(obj->name, mod->name))
				continue;

			obj->mod = mod;

			ret = klp_init_object_loaded(patch, obj);
			if (ret) {
				pr_warn("failed to initialize patch '%s' for module '%s' (%d)\n",
					patch->mod->name, obj->mod->name, ret);
				goto err;
			}

			/*
			 * Only patch the module if the patch is enabled or is
			 * in transition.
			 */
			if (!patch->enabled && patch != klp_transition_patch)
				break;

			pr_notice("applying patch '%s' to loading module '%s'\n",
				  patch->mod->name, obj->mod->name);

			ret = klp_pre_patch_callback(obj);
			if (ret) {
				pr_warn("pre-patch callback failed for object '%s'\n",
					obj->name);
				goto err;
			}

			ret = klp_patch_object(obj);
			if (ret) {
				pr_warn("failed to apply patch '%s' to module '%s' (%d)\n",
					patch->mod->name, obj->mod->name, ret);

				klp_post_unpatch_callback(obj);
				goto err;
			}

			if (patch != klp_transition_patch)
				klp_post_patch_callback(obj);

			break;
		}
	}

	mutex_unlock(&klp_mutex);

	return 0;

err:
	/*
	 * If a patch is unsuccessfully applied, return
	 * error to the module loader.
	 */
	pr_warn("patch '%s' failed for module '%s', refusing to load module '%s'\n",
		patch->mod->name, obj->mod->name, obj->mod->name);
	mod->klp_alive = false;
	klp_cleanup_module_patches_limited(mod, patch);
	mutex_unlock(&klp_mutex);

	return ret;
}

void klp_module_going(struct module *mod)
{
	if (WARN_ON(mod->state != MODULE_STATE_GOING &&
		    mod->state != MODULE_STATE_COMING))
		return;

	mutex_lock(&klp_mutex);
	/*
	 * Each module has to know that klp_module_going()
	 * has been called. We never know what module will
	 * get patched by a new patch.
	 */
	mod->klp_alive = false;

	klp_cleanup_module_patches_limited(mod, NULL);

	mutex_unlock(&klp_mutex);
}

static int __init klp_init(void)
{
	int ret;

	ret = klp_check_compiler_support();
	if (ret) {
		pr_info("Your compiler is too old; turning off.\n");
		return -EINVAL;
	}

	klp_root_kobj = kobject_create_and_add("livepatch", kernel_kobj);
	if (!klp_root_kobj)
		return -ENOMEM;

	return 0;
}

module_init(klp_init);


static void bpf_array_free_percpu(struct bpf_array *array)
{
	int i;

	for (i = 0; i < array->map.max_entries; i++) {
		free_percpu(array->pptrs[i]);
		cond_resched();
	}
}

static int bpf_array_alloc_percpu(struct bpf_array *array)
{
	void __percpu *ptr;
	int i;

	for (i = 0; i < array->map.max_entries; i++) {
		ptr = __alloc_percpu_gfp(array->elem_size, 8,
					 GFP_USER | __GFP_NOWARN);
		if (!ptr) {
			bpf_array_free_percpu(array);
			return -ENOMEM;
		}
		array->pptrs[i] = ptr;
		cond_resched();
	}

	return 0;
}

/* Called from syscall */
int array_map_alloc_check(union bpf_attr *attr)
{
	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	int numa_node = bpf_map_attr_numa_node(attr);

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size == 0 ||
	    attr->map_flags & ~ARRAY_CREATE_FLAG_MASK ||
	    (percpu && numa_node != NUMA_NO_NODE))
		return -EINVAL;

	if (attr->value_size > KMALLOC_MAX_SIZE)
		/* if value_size is bigger, the user space won't be able to
		 * access the elements.
		 */
		return -E2BIG;

	return 0;
}

static struct bpf_map *array_map_alloc(union bpf_attr *attr)
{
	bool percpu = attr->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	int ret, numa_node = bpf_map_attr_numa_node(attr);
	u32 elem_size, index_mask, max_entries;
	bool unpriv = !capable(CAP_SYS_ADMIN);
	u64 cost, array_size, mask64;
	struct bpf_array *array;

	elem_size = round_up(attr->value_size, 8);

	max_entries = attr->max_entries;

	/* On 32 bit archs roundup_pow_of_two() with max_entries that has
	 * upper most bit set in u32 space is undefined behavior due to
	 * resulting 1U << 32, so do it manually here in u64 space.
	 */
	mask64 = fls_long(max_entries - 1);
	mask64 = 1ULL << mask64;
	mask64 -= 1;

	index_mask = mask64;
	if (unpriv) {
		/* round up array size to nearest power of 2,
		 * since cpu will speculate within index_mask limits
		 */
		max_entries = index_mask + 1;
		/* Check for overflows. */
		if (max_entries < attr->max_entries)
			return ERR_PTR(-E2BIG);
	}

	array_size = sizeof(*array);
	if (percpu)
		array_size += (u64) max_entries * sizeof(void *);
	else
		array_size += (u64) max_entries * elem_size;

	/* make sure there is no u32 overflow later in round_up() */
	cost = array_size;
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-ENOMEM);
	if (percpu) {
		cost += (u64)attr->max_entries * elem_size * num_possible_cpus();
		if (cost >= U32_MAX - PAGE_SIZE)
			return ERR_PTR(-ENOMEM);
	}
	cost = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	ret = bpf_map_precharge_memlock(cost);
	if (ret < 0)
		return ERR_PTR(ret);

	/* allocate all map elements and zero-initialize them */
	array = bpf_map_area_alloc(array_size, numa_node);
	if (!array)
		return ERR_PTR(-ENOMEM);
	array->index_mask = index_mask;
	array->map.unpriv_array = unpriv;

	/* copy mandatory map attributes */
	bpf_map_init_from_attr(&array->map, attr);
	array->map.pages = cost;
	array->elem_size = elem_size;

	if (percpu && bpf_array_alloc_percpu(array)) {
		bpf_map_area_free(array);
		return ERR_PTR(-ENOMEM);
	}

	return &array->map;
}

/* Called from syscall or from eBPF program */
static void *array_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	return array->value + array->elem_size * (index & array->index_mask);
}

/* emit BPF instructions equivalent to C code of array_map_lookup_elem() */
static u32 array_map_gen_lookup(struct bpf_map *map, struct bpf_insn *insn_buf)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_insn *insn = insn_buf;
	u32 elem_size = round_up(map->value_size, 8);
	const int ret = BPF_REG_0;
	const int map_ptr = BPF_REG_1;
	const int index = BPF_REG_2;

	*insn++ = BPF_ALU64_IMM(BPF_ADD, map_ptr, offsetof(struct bpf_array, value));
	*insn++ = BPF_LDX_MEM(BPF_W, ret, index, 0);
	if (map->unpriv_array) {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 4);
		*insn++ = BPF_ALU32_IMM(BPF_AND, ret, array->index_mask);
	} else {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 3);
	}

	if (is_power_of_2(elem_size)) {
		*insn++ = BPF_ALU64_IMM(BPF_LSH, ret, ilog2(elem_size));
	} else {
		*insn++ = BPF_ALU64_IMM(BPF_MUL, ret, elem_size);
	}
	*insn++ = BPF_ALU64_REG(BPF_ADD, ret, map_ptr);
	*insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
	*insn++ = BPF_MOV64_IMM(ret, 0);
	return insn - insn_buf;
}

/* Called from eBPF program */
static void *percpu_array_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	return this_cpu_ptr(array->pptrs[index & array->index_mask]);
}

int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	void __percpu *pptr;
	int cpu, off = 0;
	u32 size;

	if (unlikely(index >= array->map.max_entries))
		return -ENOENT;

	/* per_cpu areas are zero-filled and bpf programs can only
	 * access 'value_size' of them, so copying rounded areas
	 * will not leak any kernel data
	 */
	size = round_up(map->value_size, 8);
	rcu_read_lock();
	pptr = array->pptrs[index & array->index_mask];
	for_each_possible_cpu(cpu) {
		bpf_long_memcpy(value + off, per_cpu_ptr(pptr, cpu), size);
		off += size;
	}
	rcu_read_unlock();
	return 0;
}

/* Called from syscall */
static int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= array->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == array->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}

/* Called from syscall or from eBPF program */
static int array_map_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(map_flags > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	if (unlikely(index >= array->map.max_entries))
		/* all elements were pre-allocated, cannot insert a new one */
		return -E2BIG;

	if (unlikely(map_flags == BPF_NOEXIST))
		/* all elements already exist */
		return -EEXIST;

	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		memcpy(this_cpu_ptr(array->pptrs[index & array->index_mask]),
		       value, map->value_size);
	else
		memcpy(array->value +
		       array->elem_size * (index & array->index_mask),
		       value, map->value_size);
	return 0;
}

int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
			    u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	void __percpu *pptr;
	int cpu, off = 0;
	u32 size;

	if (unlikely(map_flags > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	if (unlikely(index >= array->map.max_entries))
		/* all elements were pre-allocated, cannot insert a new one */
		return -E2BIG;

	if (unlikely(map_flags == BPF_NOEXIST))
		/* all elements already exist */
		return -EEXIST;

	/* the user space will provide round_up(value_size, 8) bytes that
	 * will be copied into per-cpu area. bpf programs can only access
	 * value_size of it. During lookup the same extra bytes will be
	 * returned or zeros which were zero-filled by percpu_alloc,
	 * so no kernel data leaks possible
	 */
	size = round_up(map->value_size, 8);
	rcu_read_lock();
	pptr = array->pptrs[index & array->index_mask];
	for_each_possible_cpu(cpu) {
		bpf_long_memcpy(per_cpu_ptr(pptr, cpu), value + off, size);
		off += size;
	}
	rcu_read_unlock();
	return 0;
}

/* Called from syscall or from eBPF program */
static int array_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;
}

/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
static void array_map_free(struct bpf_map *map)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);

	/* at this point bpf_prog->aux->refcnt == 0 and this map->refcnt == 0,
	 * so the programs (can be more than one that used this map) were
	 * disconnected from events. Wait for outstanding programs to complete
	 * and free the array
	 */
	synchronize_rcu();

	if (array->map.map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		bpf_array_free_percpu(array);

	bpf_map_area_free(array);
}

static void array_map_seq_show_elem(struct bpf_map *map, void *key,
				    struct seq_file *m)
{
	void *value;

	rcu_read_lock();

	value = array_map_lookup_elem(map, key);
	if (!value) {
		rcu_read_unlock();
		return;
	}

	seq_printf(m, "%u: ", *(u32 *)key);
	btf_type_seq_show(map->btf, map->btf_value_type_id, value, m);
	seq_puts(m, "\n");

	rcu_read_unlock();
}

static void percpu_array_map_seq_show_elem(struct bpf_map *map, void *key,
					   struct seq_file *m)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;
	void __percpu *pptr;
	int cpu;

	rcu_read_lock();

	seq_printf(m, "%u: {\n", *(u32 *)key);
	pptr = array->pptrs[index & array->index_mask];
	for_each_possible_cpu(cpu) {
		seq_printf(m, "\tcpu%d: ", cpu);
		btf_type_seq_show(map->btf, map->btf_value_type_id,
				  per_cpu_ptr(pptr, cpu), m);
		seq_puts(m, "\n");
	}
	seq_puts(m, "}\n");

	rcu_read_unlock();
}

static int array_map_check_btf(const struct bpf_map *map,
			       const struct btf_type *key_type,
			       const struct btf_type *value_type)
{
	u32 int_data;

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	/* bpf array can only take a u32 key. This check makes sure
	 * that the btf matches the attr used during map_create.
	 */
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}

const struct bpf_map_ops array_map_ops = {
	.map_alloc_check = array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = array_map_lookup_elem,
	.map_update_elem = array_map_update_elem,
	.map_delete_elem = array_map_delete_elem,
	.map_gen_lookup = array_map_gen_lookup,
	.map_seq_show_elem = array_map_seq_show_elem,
	.map_check_btf = array_map_check_btf,
};

const struct bpf_map_ops percpu_array_map_ops = {
	.map_alloc_check = array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = percpu_array_map_lookup_elem,
	.map_update_elem = array_map_update_elem,
	.map_delete_elem = array_map_delete_elem,
	.map_seq_show_elem = percpu_array_map_seq_show_elem,
	.map_check_btf = array_map_check_btf,
};

static int fd_array_map_alloc_check(union bpf_attr *attr)
{
	/* only file descriptors can be stored in this type of map */
	if (attr->value_size != sizeof(u32))
		return -EINVAL;
	return array_map_alloc_check(attr);
}

static void fd_array_map_free(struct bpf_map *map)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	int i;

	synchronize_rcu();

	/* make sure it's empty */
	for (i = 0; i < array->map.max_entries; i++)
		BUG_ON(array->ptrs[i] != NULL);

	bpf_map_area_free(array);
}

static void *fd_array_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

/* only called from syscall */
int bpf_fd_array_map_lookup_elem(struct bpf_map *map, void *key, u32 *value)
{
	void **elem, *ptr;
	int ret =  0;

	if (!map->ops->map_fd_sys_lookup_elem)
		return -ENOTSUPP;

	rcu_read_lock();
	elem = array_map_lookup_elem(map, key);
	if (elem && (ptr = READ_ONCE(*elem)))
		*value = map->ops->map_fd_sys_lookup_elem(ptr);
	else
		ret = -ENOENT;
	rcu_read_unlock();

	return ret;
}

/* only called from syscall */
int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
				 void *key, void *value, u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *new_ptr, *old_ptr;
	u32 index = *(u32 *)key, ufd;

	if (map_flags != BPF_ANY)
		return -EINVAL;

	if (index >= array->map.max_entries)
		return -E2BIG;

	ufd = *(u32 *)value;
	new_ptr = map->ops->map_fd_get_ptr(map, map_file, ufd);
	if (IS_ERR(new_ptr))
		return PTR_ERR(new_ptr);

	old_ptr = xchg(array->ptrs + index, new_ptr);
	if (old_ptr)
		map->ops->map_fd_put_ptr(old_ptr);

	return 0;
}

static int fd_array_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *old_ptr;
	u32 index = *(u32 *)key;

	if (index >= array->map.max_entries)
		return -E2BIG;

	old_ptr = xchg(array->ptrs + index, NULL);
	if (old_ptr) {
		map->ops->map_fd_put_ptr(old_ptr);
		return 0;
	} else {
		return -ENOENT;
	}
}

static void *prog_fd_array_get_ptr(struct bpf_map *map,
				   struct file *map_file, int fd)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_prog *prog = bpf_prog_get(fd);

	if (IS_ERR(prog))
		return prog;

	if (!bpf_prog_array_compatible(array, prog)) {
		bpf_prog_put(prog);
		return ERR_PTR(-EINVAL);
	}

	return prog;
}

static void prog_fd_array_put_ptr(void *ptr)
{
	bpf_prog_put(ptr);
}

static u32 prog_fd_array_sys_lookup_elem(void *ptr)
{
	return ((struct bpf_prog *)ptr)->aux->id;
}

/* decrement refcnt of all bpf_progs that are stored in this map */
static void bpf_fd_array_map_clear(struct bpf_map *map)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	int i;

	for (i = 0; i < array->map.max_entries; i++)
		fd_array_map_delete_elem(map, &i);
}

static void prog_array_map_seq_show_elem(struct bpf_map *map, void *key,
					 struct seq_file *m)
{
	void **elem, *ptr;
	u32 prog_id;

	rcu_read_lock();

	elem = array_map_lookup_elem(map, key);
	if (elem) {
		ptr = READ_ONCE(*elem);
		if (ptr) {
			seq_printf(m, "%u: ", *(u32 *)key);
			prog_id = prog_fd_array_sys_lookup_elem(ptr);
			btf_type_seq_show(map->btf, map->btf_value_type_id,
					  &prog_id, m);
			seq_puts(m, "\n");
		}
	}

	rcu_read_unlock();
}

const struct bpf_map_ops prog_array_map_ops = {
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = fd_array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = fd_array_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = prog_fd_array_get_ptr,
	.map_fd_put_ptr = prog_fd_array_put_ptr,
	.map_fd_sys_lookup_elem = prog_fd_array_sys_lookup_elem,
	.map_release_uref = bpf_fd_array_map_clear,
	.map_seq_show_elem = prog_array_map_seq_show_elem,
};

static struct bpf_event_entry *bpf_event_entry_gen(struct file *perf_file,
						   struct file *map_file)
{
	struct bpf_event_entry *ee;

	ee = kzalloc(sizeof(*ee), GFP_ATOMIC);
	if (ee) {
		ee->event = perf_file->private_data;
		ee->perf_file = perf_file;
		ee->map_file = map_file;
	}

	return ee;
}

static void __bpf_event_entry_free(struct rcu_head *rcu)
{
	struct bpf_event_entry *ee;

	ee = container_of(rcu, struct bpf_event_entry, rcu);
	fput(ee->perf_file);
	kfree(ee);
}

static void bpf_event_entry_free_rcu(struct bpf_event_entry *ee)
{
	call_rcu(&ee->rcu, __bpf_event_entry_free);
}

static void *perf_event_fd_array_get_ptr(struct bpf_map *map,
					 struct file *map_file, int fd)
{
	struct bpf_event_entry *ee;
	struct perf_event *event;
	struct file *perf_file;
	u64 value;

	perf_file = perf_event_get(fd);
	if (IS_ERR(perf_file))
		return perf_file;

	ee = ERR_PTR(-EOPNOTSUPP);
	event = perf_file->private_data;
	if (perf_event_read_local(event, &value, NULL, NULL) == -EOPNOTSUPP)
		goto err_out;

	ee = bpf_event_entry_gen(perf_file, map_file);
	if (ee)
		return ee;
	ee = ERR_PTR(-ENOMEM);
err_out:
	fput(perf_file);
	return ee;
}

static void perf_event_fd_array_put_ptr(void *ptr)
{
	bpf_event_entry_free_rcu(ptr);
}

static void perf_event_fd_array_release(struct bpf_map *map,
					struct file *map_file)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	struct bpf_event_entry *ee;
	int i;

	rcu_read_lock();
	for (i = 0; i < array->map.max_entries; i++) {
		ee = READ_ONCE(array->ptrs[i]);
		if (ee && ee->map_file == map_file)
			fd_array_map_delete_elem(map, &i);
	}
	rcu_read_unlock();
}

const struct bpf_map_ops perf_event_array_map_ops = {
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = fd_array_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = fd_array_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = perf_event_fd_array_get_ptr,
	.map_fd_put_ptr = perf_event_fd_array_put_ptr,
	.map_release = perf_event_fd_array_release,
	.map_check_btf = map_check_no_btf,
};

#ifdef CONFIG_CGROUPS
static void *cgroup_fd_array_get_ptr(struct bpf_map *map,
				     struct file *map_file /* not used */,
				     int fd)
{
	return cgroup_get_from_fd(fd);
}

static void cgroup_fd_array_put_ptr(void *ptr)
{
	/* cgroup_put free cgrp after a rcu grace period */
	cgroup_put(ptr);
}

static void cgroup_fd_array_free(struct bpf_map *map)
{
	bpf_fd_array_map_clear(map);
	fd_array_map_free(map);
}

const struct bpf_map_ops cgroup_array_map_ops = {
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_map_alloc,
	.map_free = cgroup_fd_array_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = fd_array_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = cgroup_fd_array_get_ptr,
	.map_fd_put_ptr = cgroup_fd_array_put_ptr,
	.map_check_btf = map_check_no_btf,
};
#endif

static struct bpf_map *array_of_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map, *inner_map_meta;

	inner_map_meta = bpf_map_meta_alloc(attr->inner_map_fd);
	if (IS_ERR(inner_map_meta))
		return inner_map_meta;

	map = array_map_alloc(attr);
	if (IS_ERR(map)) {
		bpf_map_meta_free(inner_map_meta);
		return map;
	}

	map->inner_map_meta = inner_map_meta;

	return map;
}

static void array_of_map_free(struct bpf_map *map)
{
	/* map->inner_map_meta is only accessed by syscall which
	 * is protected by fdget/fdput.
	 */
	bpf_map_meta_free(map->inner_map_meta);
	bpf_fd_array_map_clear(map);
	fd_array_map_free(map);
}

static void *array_of_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map = array_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}

static u32 array_of_map_gen_lookup(struct bpf_map *map,
				   struct bpf_insn *insn_buf)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 elem_size = round_up(map->value_size, 8);
	struct bpf_insn *insn = insn_buf;
	const int ret = BPF_REG_0;
	const int map_ptr = BPF_REG_1;
	const int index = BPF_REG_2;

	*insn++ = BPF_ALU64_IMM(BPF_ADD, map_ptr, offsetof(struct bpf_array, value));
	*insn++ = BPF_LDX_MEM(BPF_W, ret, index, 0);
	if (map->unpriv_array) {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 6);
		*insn++ = BPF_ALU32_IMM(BPF_AND, ret, array->index_mask);
	} else {
		*insn++ = BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 5);
	}
	if (is_power_of_2(elem_size))
		*insn++ = BPF_ALU64_IMM(BPF_LSH, ret, ilog2(elem_size));
	else
		*insn++ = BPF_ALU64_IMM(BPF_MUL, ret, elem_size);
	*insn++ = BPF_ALU64_REG(BPF_ADD, ret, map_ptr);
	*insn++ = BPF_LDX_MEM(BPF_DW, ret, ret, 0);
	*insn++ = BPF_JMP_IMM(BPF_JEQ, ret, 0, 1);
	*insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
	*insn++ = BPF_MOV64_IMM(ret, 0);

	return insn - insn_buf;
}

const struct bpf_map_ops array_of_maps_map_ops = {
	.map_alloc_check = fd_array_map_alloc_check,
	.map_alloc = array_of_map_alloc,
	.map_free = array_of_map_free,
	.map_get_next_key = array_map_get_next_key,
	.map_lookup_elem = array_of_map_lookup_elem,
	.map_delete_elem = fd_array_map_delete_elem,
	.map_fd_get_ptr = bpf_map_fd_get_ptr,
	.map_fd_put_ptr = bpf_map_fd_put_ptr,
	.map_fd_sys_lookup_elem = bpf_map_fd_sys_lookup_elem,
	.map_gen_lookup = array_of_map_gen_lookup,
	.map_check_btf = map_check_no_btf,
  };
  
#define BITS_PER_U64 (sizeof(u64) * BITS_PER_BYTE)
#define BITS_PER_BYTE_MASK (BITS_PER_BYTE - 1)
#define BITS_PER_BYTE_MASKED(bits) ((bits) & BITS_PER_BYTE_MASK)
#define BITS_ROUNDDOWN_BYTES(bits) ((bits) >> 3)
#define BITS_ROUNDUP_BYTES(bits) \
	(BITS_ROUNDDOWN_BYTES(bits) + !!BITS_PER_BYTE_MASKED(bits))

#define BTF_INFO_MASK 0x0f00ffff
#define BTF_INT_MASK 0x0fffffff
#define BTF_TYPE_ID_VALID(type_id) ((type_id) <= BTF_MAX_TYPE)
#define BTF_STR_OFFSET_VALID(name_off) ((name_off) <= BTF_MAX_NAME_OFFSET)

/* 16MB for 64k structs and each has 16 members and
 * a few MB spaces for the string section.
 * The hard limit is S32_MAX.
 */
#define BTF_MAX_SIZE (16 * 1024 * 1024)

#define for_each_member(i, struct_type, member)			\
	for (i = 0, member = btf_type_member(struct_type);	\
	     i < btf_type_vlen(struct_type);			\
	     i++, member++)

#define for_each_member_from(i, from, struct_type, member)		\
	for (i = from, member = btf_type_member(struct_type) + from;	\
	     i < btf_type_vlen(struct_type);				\
	     i++, member++)

static DEFINE_IDR(btf_idr);
static DEFINE_SPINLOCK(btf_idr_lock);

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct rcu_head rcu;
};

enum verifier_phase {
	CHECK_META,
	CHECK_TYPE,
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum visit_state {
	NOT_VISITED,
	VISITED,
	RESOLVED,
};

enum resolve_mode {
	RESOLVE_TBD,	/* To Be Determined */
	RESOLVE_PTR,	/* Resolving for Pointer */
	RESOLVE_STRUCT_OR_ARRAY,	/* Resolving for struct/union
					 * or array
					 */
};

#define MAX_RESOLVE_DEPTH 32

struct btf_sec_info {
	u32 off;
	u32 len;
};

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[MAX_RESOLVE_DEPTH];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

static const char * const btf_kind_str[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
};

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *env,
			  const struct btf_type *t,
			  u32 meta_left);
	int (*resolve)(struct btf_verifier_env *env,
		       const struct resolve_vertex *v);
	int (*check_member)(struct btf_verifier_env *env,
			    const struct btf_type *struct_type,
			    const struct btf_member *member,
			    const struct btf_type *member_type);
	void (*log_details)(struct btf_verifier_env *env,
			    const struct btf_type *t);
	void (*seq_show)(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offsets,
			 struct seq_file *m);
};

static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS];
static struct btf_type btf_void;

static bool btf_type_is_modifier(const struct btf_type *t)
{
	/* Some of them is not strictly a C modifier
	 * but they are grouped into the same bucket
	 * for BTF concern:
	 *   A type (t) that refers to another
	 *   type through t->type AND its size cannot
	 *   be determined without following the t->type.
	 *
	 * ptr does not fall into this bucket
	 * because its size is always sizeof(void *).
	 */
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
		return true;
	}

	return false;
}

static bool btf_type_is_void(const struct btf_type *t)
{
	/* void => no type and size info.
	 * Hence, FWD is also treated as void.
	 */
	return t == &btf_void || BTF_INFO_KIND(t->info) == BTF_KIND_FWD;
}

static bool btf_type_is_void_or_null(const struct btf_type *t)
{
	return !t || btf_type_is_void(t);
}

/* union is only a special case of struct:
 * all its offsetof(member) == 0
 */
static bool btf_type_is_struct(const struct btf_type *t)
{
	u8 kind = BTF_INFO_KIND(t->info);

	return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION;
}

static bool btf_type_is_array(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_ARRAY;
}

static bool btf_type_is_ptr(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_PTR;
}

static bool btf_type_is_int(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_INT;
}

/* What types need to be resolved?
 *
 * btf_type_is_modifier() is an obvious one.
 *
 * btf_type_is_struct() because its member refers to
 * another type (through member->type).
 * btf_type_is_array() because its element (array->type)
 * refers to another type.  Array can be thought of a
 * special case of struct while array just has the same
 * member-type repeated by array->nelems of times.
 */
static bool btf_type_needs_resolve(const struct btf_type *t)
{
	return btf_type_is_modifier(t) ||
		btf_type_is_ptr(t) ||
		btf_type_is_struct(t) ||
		btf_type_is_array(t);
}

/* t->size can be used */
static bool btf_type_has_size(const struct btf_type *t)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM:
		return true;
	}

	return false;
}

static const char *btf_int_encoding_str(u8 encoding)
{
	if (encoding == 0)
		return "(none)";
	else if (encoding == BTF_INT_SIGNED)
		return "SIGNED";
	else if (encoding == BTF_INT_CHAR)
		return "CHAR";
	else if (encoding == BTF_INT_BOOL)
		return "BOOL";
	else
		return "UNKN";
}

static u16 btf_type_vlen(const struct btf_type *t)
{
	return BTF_INFO_VLEN(t->info);
}

static u32 btf_type_int(const struct btf_type *t)
{
	return *(u32 *)(t + 1);
}

static const struct btf_array *btf_type_array(const struct btf_type *t)
{
	return (const struct btf_array *)(t + 1);
}

static const struct btf_member *btf_type_member(const struct btf_type *t)
{
	return (const struct btf_member *)(t + 1);
}

static const struct btf_enum *btf_type_enum(const struct btf_type *t)
{
	return (const struct btf_enum *)(t + 1);
}

static const struct btf_kind_operations *btf_type_ops(const struct btf_type *t)
{
	return kind_ops[BTF_INFO_KIND(t->info)];
}

static bool btf_name_offset_valid(const struct btf *btf, u32 offset)
{
	return BTF_STR_OFFSET_VALID(offset) &&
		offset < btf->hdr.str_len;
}

static const char *btf_name_by_offset(const struct btf *btf, u32 offset)
{
	if (!offset)
		return "(anon)";
	else if (offset < btf->hdr.str_len)
		return &btf->strings[offset];
	else
		return "(invalid-name-offset)";
}

static const struct btf_type *btf_type_by_id(const struct btf *btf, u32 type_id)
{
	if (type_id > btf->nr_types)
		return NULL;

	return btf->types[type_id];
}

/*
 * Regular int is not a bit field and it must be either
 * u8/u16/u32/u64.
 */
static bool btf_type_int_is_regular(const struct btf_type *t)
{
	u8 nr_bits, nr_bytes;
	u32 int_data;

	int_data = btf_type_int(t);
	nr_bits = BTF_INT_BITS(int_data);
	nr_bytes = BITS_ROUNDUP_BYTES(nr_bits);
	if (BITS_PER_BYTE_MASKED(nr_bits) ||
	    BTF_INT_OFFSET(int_data) ||
	    (nr_bytes != sizeof(u8) && nr_bytes != sizeof(u16) &&
	     nr_bytes != sizeof(u32) && nr_bytes != sizeof(u64))) {
		return false;
	}

	return true;
}

__printf(2, 3) static void __btf_verifier_log(struct bpf_verifier_log *log,
					      const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

__printf(2, 3) static void btf_verifier_log(struct btf_verifier_env *env,
					    const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

__printf(4, 5) static void __btf_verifier_log_type(struct btf_verifier_env *env,
						   const struct btf_type *t,
						   bool log_details,
						   const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	u8 kind = BTF_INFO_KIND(t->info);
	struct btf *btf = env->btf;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	__btf_verifier_log(log, "[%u] %s %s%s",
			   env->log_type_id,
			   btf_kind_str[kind],
			   btf_name_by_offset(btf, t->name_off),
			   log_details ? " " : "");

	if (log_details)
		btf_type_ops(t)->log_details(env, t);

	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

#define btf_verifier_log_type(env, t, ...) \
	__btf_verifier_log_type((env), (t), true, __VA_ARGS__)
#define btf_verifier_log_basic(env, t, ...) \
	__btf_verifier_log_type((env), (t), false, __VA_ARGS__)

__printf(4, 5)
static void btf_verifier_log_member(struct btf_verifier_env *env,
				    const struct btf_type *struct_type,
				    const struct btf_member *member,
				    const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	struct btf *btf = env->btf;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	/* The CHECK_META phase already did a btf dump.
	 *
	 * If member is logged again, it must hit an error in
	 * parsing this member.  It is useful to print out which
	 * struct this member belongs to.
	 */
	if (env->phase != CHECK_META)
		btf_verifier_log_type(env, struct_type, NULL);

	__btf_verifier_log(log, "\t%s type_id=%u bits_offset=%u",
			   btf_name_by_offset(btf, member->name_off),
			   member->type, member->offset);

	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

static void btf_verifier_log_hdr(struct btf_verifier_env *env,
				 u32 btf_data_size)
{
	struct bpf_verifier_log *log = &env->log;
	const struct btf *btf = env->btf;
	const struct btf_header *hdr;

	if (!bpf_verifier_log_needed(log))
		return;

	hdr = &btf->hdr;
	__btf_verifier_log(log, "magic: 0x%x\n", hdr->magic);
	__btf_verifier_log(log, "version: %u\n", hdr->version);
	__btf_verifier_log(log, "flags: 0x%x\n", hdr->flags);
	__btf_verifier_log(log, "hdr_len: %u\n", hdr->hdr_len);
	__btf_verifier_log(log, "type_off: %u\n", hdr->type_off);
	__btf_verifier_log(log, "type_len: %u\n", hdr->type_len);
	__btf_verifier_log(log, "str_off: %u\n", hdr->str_off);
	__btf_verifier_log(log, "str_len: %u\n", hdr->str_len);
	__btf_verifier_log(log, "btf_total_size: %u\n", btf_data_size);
}

static int btf_add_type(struct btf_verifier_env *env, struct btf_type *t)
{
	struct btf *btf = env->btf;

	/* < 2 because +1 for btf_void which is always in btf->types[0].
	 * btf_void is not accounted in btf->nr_types because btf_void
	 * does not come from the BTF file.
	 */
	if (btf->types_size - btf->nr_types < 2) {
		/* Expand 'types' array */

		struct btf_type **new_types;
		u32 expand_by, new_size;

		if (btf->types_size == BTF_MAX_TYPE) {
			btf_verifier_log(env, "Exceeded max num of types");
			return -E2BIG;
		}

		expand_by = max_t(u32, btf->types_size >> 2, 16);
		new_size = min_t(u32, BTF_MAX_TYPE,
				 btf->types_size + expand_by);

		new_types = kvcalloc(new_size, sizeof(*new_types),
				     GFP_KERNEL | __GFP_NOWARN);
		if (!new_types)
			return -ENOMEM;

		if (btf->nr_types == 0)
			new_types[0] = &btf_void;
		else
			memcpy(new_types, btf->types,
			       sizeof(*btf->types) * (btf->nr_types + 1));

		kvfree(btf->types);
		btf->types = new_types;
		btf->types_size = new_size;
	}

	btf->types[++(btf->nr_types)] = t;

	return 0;
}

static int btf_alloc_id(struct btf *btf)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&btf_idr_lock);
	id = idr_alloc_cyclic(&btf_idr, btf, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		btf->id = id;
	spin_unlock_bh(&btf_idr_lock);
	idr_preload_end();

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

static void btf_free_id(struct btf *btf)
{
	unsigned long flags;

	/*
	 * In map-in-map, calling map_delete_elem() on outer
	 * map will call bpf_map_put on the inner map.
	 * It will then eventually call btf_free_id()
	 * on the inner map.  Some of the map_delete_elem()
	 * implementation may have irq disabled, so
	 * we need to use the _irqsave() version instead
	 * of the _bh() version.
	 */
	spin_lock_irqsave(&btf_idr_lock, flags);
	idr_remove(&btf_idr, btf->id);
	spin_unlock_irqrestore(&btf_idr_lock, flags);
}

static void btf_free(struct btf *btf)
{
	kvfree(btf->types);
	kvfree(btf->resolved_sizes);
	kvfree(btf->resolved_ids);
	kvfree(btf->data);
	kfree(btf);
}

static void btf_free_rcu(struct rcu_head *rcu)
{
	struct btf *btf = container_of(rcu, struct btf, rcu);

	btf_free(btf);
}

void btf_put(struct btf *btf)
{
	if (btf && refcount_dec_and_test(&btf->refcnt)) {
		btf_free_id(btf);
		call_rcu(&btf->rcu, btf_free_rcu);
	}
}

static int env_resolve_init(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	u32 nr_types = btf->nr_types;
	u32 *resolved_sizes = NULL;
	u32 *resolved_ids = NULL;
	u8 *visit_states = NULL;

	/* +1 for btf_void */
	resolved_sizes = kvcalloc(nr_types + 1, sizeof(*resolved_sizes),
				  GFP_KERNEL | __GFP_NOWARN);
	if (!resolved_sizes)
		goto nomem;

	resolved_ids = kvcalloc(nr_types + 1, sizeof(*resolved_ids),
				GFP_KERNEL | __GFP_NOWARN);
	if (!resolved_ids)
		goto nomem;

	visit_states = kvcalloc(nr_types + 1, sizeof(*visit_states),
				GFP_KERNEL | __GFP_NOWARN);
	if (!visit_states)
		goto nomem;

	btf->resolved_sizes = resolved_sizes;
	btf->resolved_ids = resolved_ids;
	env->visit_states = visit_states;

	return 0;

nomem:
	kvfree(resolved_sizes);
	kvfree(resolved_ids);
	kvfree(visit_states);
	return -ENOMEM;
}

static void btf_verifier_env_free(struct btf_verifier_env *env)
{
	kvfree(env->visit_states);
	kfree(env);
}

static bool env_type_is_resolve_sink(const struct btf_verifier_env *env,
				     const struct btf_type *next_type)
{
	switch (env->resolve_mode) {
	case RESOLVE_TBD:
		/* int, enum or void is a sink */
		return !btf_type_needs_resolve(next_type);
	case RESOLVE_PTR:
		/* int, enum, void, struct or array is a sink for ptr */
		return !btf_type_is_modifier(next_type) &&
			!btf_type_is_ptr(next_type);
	case RESOLVE_STRUCT_OR_ARRAY:
		/* int, enum, void or ptr is a sink for struct and array */
		return !btf_type_is_modifier(next_type) &&
			!btf_type_is_array(next_type) &&
			!btf_type_is_struct(next_type);
	default:
		BUG();
	}
}

static bool env_type_is_resolved(const struct btf_verifier_env *env,
				 u32 type_id)
{
	return env->visit_states[type_id] == RESOLVED;
}

static int env_stack_push(struct btf_verifier_env *env,
			  const struct btf_type *t, u32 type_id)
{
	struct resolve_vertex *v;

	if (env->top_stack == MAX_RESOLVE_DEPTH)
		return -E2BIG;

	if (env->visit_states[type_id] != NOT_VISITED)
		return -EEXIST;

	env->visit_states[type_id] = VISITED;

	v = &env->stack[env->top_stack++];
	v->t = t;
	v->type_id = type_id;
	v->next_member = 0;

	if (env->resolve_mode == RESOLVE_TBD) {
		if (btf_type_is_ptr(t))
			env->resolve_mode = RESOLVE_PTR;
		else if (btf_type_is_struct(t) || btf_type_is_array(t))
			env->resolve_mode = RESOLVE_STRUCT_OR_ARRAY;
	}

	return 0;
}

static void env_stack_set_next_member(struct btf_verifier_env *env,
				      u16 next_member)
{
	env->stack[env->top_stack - 1].next_member = next_member;
}

static void env_stack_pop_resolved(struct btf_verifier_env *env,
				   u32 resolved_type_id,
				   u32 resolved_size)
{
	u32 type_id = env->stack[--(env->top_stack)].type_id;
	struct btf *btf = env->btf;

	btf->resolved_sizes[type_id] = resolved_size;
	btf->resolved_ids[type_id] = resolved_type_id;
	env->visit_states[type_id] = RESOLVED;
}

static const struct resolve_vertex *env_stack_peak(struct btf_verifier_env *env)
{
	return env->top_stack ? &env->stack[env->top_stack - 1] : NULL;
}

/* The input param "type_id" must point to a needs_resolve type */
static const struct btf_type *btf_type_id_resolve(const struct btf *btf,
						  u32 *type_id)
{
	*type_id = btf->resolved_ids[*type_id];
	return btf_type_by_id(btf, *type_id);
}

const struct btf_type *btf_type_id_size(const struct btf *btf,
					u32 *type_id, u32 *ret_size)
{
	const struct btf_type *size_type;
	u32 size_type_id = *type_id;
	u32 size = 0;

	size_type = btf_type_by_id(btf, size_type_id);
	if (btf_type_is_void_or_null(size_type))
		return NULL;

	if (btf_type_has_size(size_type)) {
		size = size_type->size;
	} else if (btf_type_is_array(size_type)) {
		size = btf->resolved_sizes[size_type_id];
	} else if (btf_type_is_ptr(size_type)) {
		size = sizeof(void *);
	} else {
		if (WARN_ON_ONCE(!btf_type_is_modifier(size_type)))
			return NULL;

		size = btf->resolved_sizes[size_type_id];
		size_type_id = btf->resolved_ids[size_type_id];
		size_type = btf_type_by_id(btf, size_type_id);
		if (btf_type_is_void(size_type))
			return NULL;
	}

	*type_id = size_type_id;
	if (ret_size)
		*ret_size = size;

	return size_type;
}

static int btf_df_check_member(struct btf_verifier_env *env,
			       const struct btf_type *struct_type,
			       const struct btf_member *member,
			       const struct btf_type *member_type)
{
	btf_verifier_log_basic(env, struct_type,
			       "Unsupported check_member");
	return -EINVAL;
}

static int btf_df_resolve(struct btf_verifier_env *env,
			  const struct resolve_vertex *v)
{
	btf_verifier_log_basic(env, v->t, "Unsupported resolve");
	return -EINVAL;
}

static void btf_df_seq_show(const struct btf *btf, const struct btf_type *t,
			    u32 type_id, void *data, u8 bits_offsets,
			    struct seq_file *m)
{
	seq_printf(m, "<unsupported kind:%u>", BTF_INFO_KIND(t->info));
}

static int btf_int_check_member(struct btf_verifier_env *env,
				const struct btf_type *struct_type,
				const struct btf_member *member,
				const struct btf_type *member_type)
{
	u32 int_data = btf_type_int(member_type);
	u32 struct_bits_off = member->offset;
	u32 struct_size = struct_type->size;
	u32 nr_copy_bits;
	u32 bytes_offset;

	if (U32_MAX - struct_bits_off < BTF_INT_OFFSET(int_data)) {
		btf_verifier_log_member(env, struct_type, member,
					"bits_offset exceeds U32_MAX");
		return -EINVAL;
	}

	struct_bits_off += BTF_INT_OFFSET(int_data);
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	nr_copy_bits = BTF_INT_BITS(int_data) +
		BITS_PER_BYTE_MASKED(struct_bits_off);

	if (nr_copy_bits > BITS_PER_U64) {
		btf_verifier_log_member(env, struct_type, member,
					"nr_copy_bits exceeds 64");
		return -EINVAL;
	}

	if (struct_size < bytes_offset ||
	    struct_size - bytes_offset < BITS_ROUNDUP_BYTES(nr_copy_bits)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_int_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	u32 int_data, nr_bits, meta_needed = sizeof(int_data);
	u16 encoding;

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	int_data = btf_type_int(t);
	if (int_data & ~BTF_INT_MASK) {
		btf_verifier_log_basic(env, t, "Invalid int_data:%x",
				       int_data);
		return -EINVAL;
	}

	nr_bits = BTF_INT_BITS(int_data) + BTF_INT_OFFSET(int_data);

	if (nr_bits > BITS_PER_U64) {
		btf_verifier_log_type(env, t, "nr_bits exceeds %zu",
				      BITS_PER_U64);
		return -EINVAL;
	}

	if (BITS_ROUNDUP_BYTES(nr_bits) > t->size) {
		btf_verifier_log_type(env, t, "nr_bits exceeds type_size");
		return -EINVAL;
	}

	/*
	 * Only one of the encoding bits is allowed and it
	 * should be sufficient for the pretty print purpose (i.e. decoding).
	 * Multiple bits can be allowed later if it is found
	 * to be insufficient.
	 */
	encoding = BTF_INT_ENCODING(int_data);
	if (encoding &&
	    encoding != BTF_INT_SIGNED &&
	    encoding != BTF_INT_CHAR &&
	    encoding != BTF_INT_BOOL) {
		btf_verifier_log_type(env, t, "Unsupported encoding");
		return -ENOTSUPP;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_int_log(struct btf_verifier_env *env,
			const struct btf_type *t)
{
	int int_data = btf_type_int(t);

	btf_verifier_log(env,
			 "size=%u bits_offset=%u nr_bits=%u encoding=%s",
			 t->size, BTF_INT_OFFSET(int_data),
			 BTF_INT_BITS(int_data),
			 btf_int_encoding_str(BTF_INT_ENCODING(int_data)));
}

static void btf_int_bits_seq_show(const struct btf *btf,
				  const struct btf_type *t,
				  void *data, u8 bits_offset,
				  struct seq_file *m)
{
	u16 left_shift_bits, right_shift_bits;
	u32 int_data = btf_type_int(t);
	u8 nr_bits = BTF_INT_BITS(int_data);
	u8 total_bits_offset;
	u8 nr_copy_bytes;
	u8 nr_copy_bits;
	u64 print_num;

	/*
	 * bits_offset is at most 7.
	 * BTF_INT_OFFSET() cannot exceed 64 bits.
	 */
	total_bits_offset = bits_offset + BTF_INT_OFFSET(int_data);
	data += BITS_ROUNDDOWN_BYTES(total_bits_offset);
	bits_offset = BITS_PER_BYTE_MASKED(total_bits_offset);
	nr_copy_bits = nr_bits + bits_offset;
	nr_copy_bytes = BITS_ROUNDUP_BYTES(nr_copy_bits);

	print_num = 0;
	memcpy(&print_num, data, nr_copy_bytes);

#ifdef __BIG_ENDIAN_BITFIELD
	left_shift_bits = bits_offset;
#else
	left_shift_bits = BITS_PER_U64 - nr_copy_bits;
#endif
	right_shift_bits = BITS_PER_U64 - nr_bits;

	print_num <<= left_shift_bits;
	print_num >>= right_shift_bits;

	seq_printf(m, "0x%llx", print_num);
}

static void btf_int_seq_show(const struct btf *btf, const struct btf_type *t,
			     u32 type_id, void *data, u8 bits_offset,
			     struct seq_file *m)
{
	u32 int_data = btf_type_int(t);
	u8 encoding = BTF_INT_ENCODING(int_data);
	bool sign = encoding & BTF_INT_SIGNED;
	u8 nr_bits = BTF_INT_BITS(int_data);

	if (bits_offset || BTF_INT_OFFSET(int_data) ||
	    BITS_PER_BYTE_MASKED(nr_bits)) {
		btf_int_bits_seq_show(btf, t, data, bits_offset, m);
		return;
	}

	switch (nr_bits) {
	case 64:
		if (sign)
			seq_printf(m, "%lld", *(s64 *)data);
		else
			seq_printf(m, "%llu", *(u64 *)data);
		break;
	case 32:
		if (sign)
			seq_printf(m, "%d", *(s32 *)data);
		else
			seq_printf(m, "%u", *(u32 *)data);
		break;
	case 16:
		if (sign)
			seq_printf(m, "%d", *(s16 *)data);
		else
			seq_printf(m, "%u", *(u16 *)data);
		break;
	case 8:
		if (sign)
			seq_printf(m, "%d", *(s8 *)data);
		else
			seq_printf(m, "%u", *(u8 *)data);
		break;
	default:
		btf_int_bits_seq_show(btf, t, data, bits_offset, m);
	}
}

static const struct btf_kind_operations int_ops = {
	.check_meta = btf_int_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_int_check_member,
	.log_details = btf_int_log,
	.seq_show = btf_int_seq_show,
};

static int btf_modifier_check_member(struct btf_verifier_env *env,
				     const struct btf_type *struct_type,
				     const struct btf_member *member,
				     const struct btf_type *member_type)
{
	const struct btf_type *resolved_type;
	u32 resolved_type_id = member->type;
	struct btf_member resolved_member;
	struct btf *btf = env->btf;

	resolved_type = btf_type_id_size(btf, &resolved_type_id, NULL);
	if (!resolved_type) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member");
		return -EINVAL;
	}

	resolved_member = *member;
	resolved_member.type = resolved_type_id;

	return btf_type_ops(resolved_type)->check_member(env, struct_type,
							 &resolved_member,
							 resolved_type);
}

static int btf_ptr_check_member(struct btf_verifier_env *env,
				const struct btf_type *struct_type,
				const struct btf_member *member,
				const struct btf_type *member_type)
{
	u32 struct_size, struct_bits_off, bytes_offset;

	struct_size = struct_type->size;
	struct_bits_off = member->offset;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	if (struct_size - bytes_offset < sizeof(void *)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_ref_type_check_meta(struct btf_verifier_env *env,
				   const struct btf_type *t,
				   u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (!BTF_TYPE_ID_VALID(t->type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static int btf_modifier_resolve(struct btf_verifier_env *env,
				const struct resolve_vertex *v)
{
	const struct btf_type *t = v->t;
	const struct btf_type *next_type;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;
	u32 next_type_size = 0;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	/* "typedef void new_void", "const void"...etc */
	if (btf_type_is_void(next_type))
		goto resolved;

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	/* Figure out the resolved next_type_id with size.
	 * They will be stored in the current modifier's
	 * resolved_ids and resolved_sizes such that it can
	 * save us a few type-following when we use it later (e.g. in
	 * pretty print).
	 */
	if (!btf_type_id_size(btf, &next_type_id, &next_type_size) &&
	    !btf_type_is_void(btf_type_id_resolve(btf, &next_type_id))) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

resolved:
	env_stack_pop_resolved(env, next_type_id, next_type_size);

	return 0;
}

static int btf_ptr_resolve(struct btf_verifier_env *env,
			   const struct resolve_vertex *v)
{
	const struct btf_type *next_type;
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;
	u32 next_type_size = 0;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	/* "void *" */
	if (btf_type_is_void(next_type))
		goto resolved;

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	/* If the modifier was RESOLVED during RESOLVE_STRUCT_OR_ARRAY,
	 * the modifier may have stopped resolving when it was resolved
	 * to a ptr (last-resolved-ptr).
	 *
	 * We now need to continue from the last-resolved-ptr to
	 * ensure the last-resolved-ptr will not referring back to
	 * the currenct ptr (t).
	 */
	if (btf_type_is_modifier(next_type)) {
		const struct btf_type *resolved_type;
		u32 resolved_type_id;

		resolved_type_id = next_type_id;
		resolved_type = btf_type_id_resolve(btf, &resolved_type_id);

		if (btf_type_is_ptr(resolved_type) &&
		    !env_type_is_resolve_sink(env, resolved_type) &&
		    !env_type_is_resolved(env, resolved_type_id))
			return env_stack_push(env, resolved_type,
					      resolved_type_id);
	}

	if (!btf_type_id_size(btf, &next_type_id, &next_type_size) &&
	    !btf_type_is_void(btf_type_id_resolve(btf, &next_type_id))) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

resolved:
	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static void btf_modifier_seq_show(const struct btf *btf,
				  const struct btf_type *t,
				  u32 type_id, void *data,
				  u8 bits_offset, struct seq_file *m)
{
	t = btf_type_id_resolve(btf, &type_id);

	btf_type_ops(t)->seq_show(btf, t, type_id, data, bits_offset, m);
}

static void btf_ptr_seq_show(const struct btf *btf, const struct btf_type *t,
			     u32 type_id, void *data, u8 bits_offset,
			     struct seq_file *m)
{
	/* It is a hashed value */
	seq_printf(m, "%p", *(void **)data);
}

static void btf_ref_type_log(struct btf_verifier_env *env,
			     const struct btf_type *t)
{
	btf_verifier_log(env, "type_id=%u", t->type);
}

static struct btf_kind_operations modifier_ops = {
	.check_meta = btf_ref_type_check_meta,
	.resolve = btf_modifier_resolve,
	.check_member = btf_modifier_check_member,
	.log_details = btf_ref_type_log,
	.seq_show = btf_modifier_seq_show,
};

static struct btf_kind_operations ptr_ops = {
	.check_meta = btf_ref_type_check_meta,
	.resolve = btf_ptr_resolve,
	.check_member = btf_ptr_check_member,
	.log_details = btf_ref_type_log,
	.seq_show = btf_ptr_seq_show,
};

static s32 btf_fwd_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (t->type) {
		btf_verifier_log_type(env, t, "type != 0");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static struct btf_kind_operations fwd_ops = {
	.check_meta = btf_fwd_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_df_check_member,
	.log_details = btf_ref_type_log,
	.seq_show = btf_df_seq_show,
};

static int btf_array_check_member(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;
	u32 array_type_id, array_size;
	struct btf *btf = env->btf;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	array_type_id = member->type;
	btf_type_id_size(btf, &array_type_id, &array_size);
	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < array_size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_array_check_meta(struct btf_verifier_env *env,
				const struct btf_type *t,
				u32 meta_left)
{
	const struct btf_array *array = btf_type_array(t);
	u32 meta_needed = sizeof(*array);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (t->size) {
		btf_verifier_log_type(env, t, "size != 0");
		return -EINVAL;
	}

	/* Array elem type and index type cannot be in type void,
	 * so !array->type and !array->index_type are not allowed.
	 */
	if (!array->type || !BTF_TYPE_ID_VALID(array->type)) {
		btf_verifier_log_type(env, t, "Invalid elem");
		return -EINVAL;
	}

	if (!array->index_type || !BTF_TYPE_ID_VALID(array->index_type)) {
		btf_verifier_log_type(env, t, "Invalid index");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static int btf_array_resolve(struct btf_verifier_env *env,
			     const struct resolve_vertex *v)
{
	const struct btf_array *array = btf_type_array(v->t);
	const struct btf_type *elem_type, *index_type;
	u32 elem_type_id, index_type_id;
	struct btf *btf = env->btf;
	u32 elem_size;

	/* Check array->index_type */
	index_type_id = array->index_type;
	index_type = btf_type_by_id(btf, index_type_id);
	if (btf_type_is_void_or_null(index_type)) {
		btf_verifier_log_type(env, v->t, "Invalid index");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, index_type) &&
	    !env_type_is_resolved(env, index_type_id))
		return env_stack_push(env, index_type, index_type_id);

	index_type = btf_type_id_size(btf, &index_type_id, NULL);
	if (!index_type || !btf_type_is_int(index_type) ||
	    !btf_type_int_is_regular(index_type)) {
		btf_verifier_log_type(env, v->t, "Invalid index");
		return -EINVAL;
	}

	/* Check array->type */
	elem_type_id = array->type;
	elem_type = btf_type_by_id(btf, elem_type_id);
	if (btf_type_is_void_or_null(elem_type)) {
		btf_verifier_log_type(env, v->t,
				      "Invalid elem");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, elem_type) &&
	    !env_type_is_resolved(env, elem_type_id))
		return env_stack_push(env, elem_type, elem_type_id);

	elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
	if (!elem_type) {
		btf_verifier_log_type(env, v->t, "Invalid elem");
		return -EINVAL;
	}

	if (btf_type_is_int(elem_type) && !btf_type_int_is_regular(elem_type)) {
		btf_verifier_log_type(env, v->t, "Invalid array of int");
		return -EINVAL;
	}

	if (array->nelems && elem_size > U32_MAX / array->nelems) {
		btf_verifier_log_type(env, v->t,
				      "Array size overflows U32_MAX");
		return -EINVAL;
	}

	env_stack_pop_resolved(env, elem_type_id, elem_size * array->nelems);

	return 0;
}

static void btf_array_log(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	const struct btf_array *array = btf_type_array(t);

	btf_verifier_log(env, "type_id=%u index_type_id=%u nr_elems=%u",
			 array->type, array->index_type, array->nelems);
}

static void btf_array_seq_show(const struct btf *btf, const struct btf_type *t,
			       u32 type_id, void *data, u8 bits_offset,
			       struct seq_file *m)
{
	const struct btf_array *array = btf_type_array(t);
	const struct btf_kind_operations *elem_ops;
	const struct btf_type *elem_type;
	u32 i, elem_size, elem_type_id;

	elem_type_id = array->type;
	elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
	elem_ops = btf_type_ops(elem_type);
	seq_puts(m, "[");
	for (i = 0; i < array->nelems; i++) {
		if (i)
			seq_puts(m, ",");

		elem_ops->seq_show(btf, elem_type, elem_type_id, data,
				   bits_offset, m);
		data += elem_size;
	}
	seq_puts(m, "]");
}

static struct btf_kind_operations array_ops = {
	.check_meta = btf_array_check_meta,
	.resolve = btf_array_resolve,
	.check_member = btf_array_check_member,
	.log_details = btf_array_log,
	.seq_show = btf_array_seq_show,
};

static int btf_struct_check_member(struct btf_verifier_env *env,
				   const struct btf_type *struct_type,
				   const struct btf_member *member,
				   const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < member_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_struct_check_meta(struct btf_verifier_env *env,
				 const struct btf_type *t,
				 u32 meta_left)
{
	bool is_union = BTF_INFO_KIND(t->info) == BTF_KIND_UNION;
	const struct btf_member *member;
	u32 meta_needed, last_offset;
	struct btf *btf = env->btf;
	u32 struct_size = t->size;
	u16 i;

	meta_needed = btf_type_vlen(t) * sizeof(*member);
	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	last_offset = 0;
	for_each_member(i, t, member) {
		if (!btf_name_offset_valid(btf, member->name_off)) {
			btf_verifier_log_member(env, t, member,
						"Invalid member name_offset:%u",
						member->name_off);
			return -EINVAL;
		}

		/* A member cannot be in type void */
		if (!member->type || !BTF_TYPE_ID_VALID(member->type)) {
			btf_verifier_log_member(env, t, member,
						"Invalid type_id");
			return -EINVAL;
		}

		if (is_union && member->offset) {
			btf_verifier_log_member(env, t, member,
						"Invalid member bits_offset");
			return -EINVAL;
		}

		/*
		 * ">" instead of ">=" because the last member could be
		 * "char a[0];"
		 */
		if (last_offset > member->offset) {
			btf_verifier_log_member(env, t, member,
						"Invalid member bits_offset");
			return -EINVAL;
		}

		if (BITS_ROUNDUP_BYTES(member->offset) > struct_size) {
			btf_verifier_log_member(env, t, member,
						"Memmber bits_offset exceeds its struct size");
			return -EINVAL;
		}

		btf_verifier_log_member(env, t, member, NULL);
		last_offset = member->offset;
	}

	return meta_needed;
}

static int btf_struct_resolve(struct btf_verifier_env *env,
			      const struct resolve_vertex *v)
{
	const struct btf_member *member;
	int err;
	u16 i;

	/* Before continue resolving the next_member,
	 * ensure the last member is indeed resolved to a
	 * type with size info.
	 */
	if (v->next_member) {
		const struct btf_type *last_member_type;
		const struct btf_member *last_member;
		u16 last_member_type_id;

		last_member = btf_type_member(v->t) + v->next_member - 1;
		last_member_type_id = last_member->type;
		if (WARN_ON_ONCE(!env_type_is_resolved(env,
						       last_member_type_id)))
			return -EINVAL;

		last_member_type = btf_type_by_id(env->btf,
						  last_member_type_id);
		err = btf_type_ops(last_member_type)->check_member(env, v->t,
							last_member,
							last_member_type);
		if (err)
			return err;
	}

	for_each_member_from(i, v->next_member, v->t, member) {
		u32 member_type_id = member->type;
		const struct btf_type *member_type = btf_type_by_id(env->btf,
								member_type_id);

		if (btf_type_is_void_or_null(member_type)) {
			btf_verifier_log_member(env, v->t, member,
						"Invalid member");
			return -EINVAL;
		}

		if (!env_type_is_resolve_sink(env, member_type) &&
		    !env_type_is_resolved(env, member_type_id)) {
			env_stack_set_next_member(env, i + 1);
			return env_stack_push(env, member_type, member_type_id);
		}

		err = btf_type_ops(member_type)->check_member(env, v->t,
							      member,
							      member_type);
		if (err)
			return err;
	}

	env_stack_pop_resolved(env, 0, 0);

	return 0;
}

static void btf_struct_log(struct btf_verifier_env *env,
			   const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}

static void btf_struct_seq_show(const struct btf *btf, const struct btf_type *t,
				u32 type_id, void *data, u8 bits_offset,
				struct seq_file *m)
{
	const char *seq = BTF_INFO_KIND(t->info) == BTF_KIND_UNION ? "|" : ",";
	const struct btf_member *member;
	u32 i;

	seq_puts(m, "{");
	for_each_member(i, t, member) {
		const struct btf_type *member_type = btf_type_by_id(btf,
								member->type);
		u32 member_offset = member->offset;
		u32 bytes_offset = BITS_ROUNDDOWN_BYTES(member_offset);
		u8 bits8_offset = BITS_PER_BYTE_MASKED(member_offset);
		const struct btf_kind_operations *ops;

		if (i)
			seq_puts(m, seq);

		ops = btf_type_ops(member_type);
		ops->seq_show(btf, member_type, member->type,
			      data + bytes_offset, bits8_offset, m);
	}
	seq_puts(m, "}");
}

static struct btf_kind_operations struct_ops = {
	.check_meta = btf_struct_check_meta,
	.resolve = btf_struct_resolve,
	.check_member = btf_struct_check_member,
	.log_details = btf_struct_log,
	.seq_show = btf_struct_seq_show,
};

static int btf_enum_check_member(struct btf_verifier_env *env,
				 const struct btf_type *struct_type,
				 const struct btf_member *member,
				 const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < sizeof(int)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_enum_check_meta(struct btf_verifier_env *env,
			       const struct btf_type *t,
			       u32 meta_left)
{
	const struct btf_enum *enums = btf_type_enum(t);
	struct btf *btf = env->btf;
	u16 i, nr_enums;
	u32 meta_needed;

	nr_enums = btf_type_vlen(t);
	meta_needed = nr_enums * sizeof(*enums);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (t->size != sizeof(int)) {
		btf_verifier_log_type(env, t, "Expected size:%zu",
				      sizeof(int));
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	for (i = 0; i < nr_enums; i++) {
		if (!btf_name_offset_valid(btf, enums[i].name_off)) {
			btf_verifier_log(env, "\tInvalid name_offset:%u",
					 enums[i].name_off);
			return -EINVAL;
		}

		btf_verifier_log(env, "\t%s val=%d\n",
				 btf_name_by_offset(btf, enums[i].name_off),
				 enums[i].val);
	}

	return meta_needed;
}

static void btf_enum_log(struct btf_verifier_env *env,
			 const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}

static void btf_enum_seq_show(const struct btf *btf, const struct btf_type *t,
			      u32 type_id, void *data, u8 bits_offset,
			      struct seq_file *m)
{
	const struct btf_enum *enums = btf_type_enum(t);
	u32 i, nr_enums = btf_type_vlen(t);
	int v = *(int *)data;

	for (i = 0; i < nr_enums; i++) {
		if (v == enums[i].val) {
			seq_printf(m, "%s",
				   btf_name_by_offset(btf, enums[i].name_off));
			return;
		}
	}

	seq_printf(m, "%d", v);
}

static struct btf_kind_operations enum_ops = {
	.check_meta = btf_enum_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_enum_check_member,
	.log_details = btf_enum_log,
	.seq_show = btf_enum_seq_show,
};

static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS] = {
	[BTF_KIND_INT] = &int_ops,
	[BTF_KIND_PTR] = &ptr_ops,
	[BTF_KIND_ARRAY] = &array_ops,
	[BTF_KIND_STRUCT] = &struct_ops,
	[BTF_KIND_UNION] = &struct_ops,
	[BTF_KIND_ENUM] = &enum_ops,
	[BTF_KIND_FWD] = &fwd_ops,
	[BTF_KIND_TYPEDEF] = &modifier_ops,
	[BTF_KIND_VOLATILE] = &modifier_ops,
	[BTF_KIND_CONST] = &modifier_ops,
	[BTF_KIND_RESTRICT] = &modifier_ops,
};

static s32 btf_check_meta(struct btf_verifier_env *env,
			  const struct btf_type *t,
			  u32 meta_left)
{
	u32 saved_meta_left = meta_left;
	s32 var_meta_size;

	if (meta_left < sizeof(*t)) {
		btf_verifier_log(env, "[%u] meta_left:%u meta_needed:%zu",
				 env->log_type_id, meta_left, sizeof(*t));
		return -EINVAL;
	}
	meta_left -= sizeof(*t);

	if (t->info & ~BTF_INFO_MASK) {
		btf_verifier_log(env, "[%u] Invalid btf_info:%x",
				 env->log_type_id, t->info);
		return -EINVAL;
	}

	if (BTF_INFO_KIND(t->info) > BTF_KIND_MAX ||
	    BTF_INFO_KIND(t->info) == BTF_KIND_UNKN) {
		btf_verifier_log(env, "[%u] Invalid kind:%u",
				 env->log_type_id, BTF_INFO_KIND(t->info));
		return -EINVAL;
	}

	if (!btf_name_offset_valid(env->btf, t->name_off)) {
		btf_verifier_log(env, "[%u] Invalid name_offset:%u",
				 env->log_type_id, t->name_off);
		return -EINVAL;
	}

	var_meta_size = btf_type_ops(t)->check_meta(env, t, meta_left);
	if (var_meta_size < 0)
		return var_meta_size;

	meta_left -= var_meta_size;

	return saved_meta_left - meta_left;
}

static int btf_check_all_metas(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	struct btf_header *hdr;
	void *cur, *end;

	hdr = &btf->hdr;
	cur = btf->nohdr_data + hdr->type_off;
	end = cur + hdr->type_len;

	env->log_type_id = 1;
	while (cur < end) {
		struct btf_type *t = cur;
		s32 meta_size;

		meta_size = btf_check_meta(env, t, end - cur);
		if (meta_size < 0)
			return meta_size;

		btf_add_type(env, t);
		cur += meta_size;
		env->log_type_id++;
	}

	return 0;
}

static int btf_resolve(struct btf_verifier_env *env,
		       const struct btf_type *t, u32 type_id)
{
	const struct resolve_vertex *v;
	int err = 0;

	env->resolve_mode = RESOLVE_TBD;
	env_stack_push(env, t, type_id);
	while (!err && (v = env_stack_peak(env))) {
		env->log_type_id = v->type_id;
		err = btf_type_ops(v->t)->resolve(env, v);
	}

	env->log_type_id = type_id;
	if (err == -E2BIG)
		btf_verifier_log_type(env, t,
				      "Exceeded max resolving depth:%u",
				      MAX_RESOLVE_DEPTH);
	else if (err == -EEXIST)
		btf_verifier_log_type(env, t, "Loop detected");

	return err;
}

static bool btf_resolve_valid(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 type_id)
{
	struct btf *btf = env->btf;

	if (!env_type_is_resolved(env, type_id))
		return false;

	if (btf_type_is_struct(t))
		return !btf->resolved_ids[type_id] &&
			!btf->resolved_sizes[type_id];

	if (btf_type_is_modifier(t) || btf_type_is_ptr(t)) {
		t = btf_type_id_resolve(btf, &type_id);
		return t && !btf_type_is_modifier(t);
	}

	if (btf_type_is_array(t)) {
		const struct btf_array *array = btf_type_array(t);
		const struct btf_type *elem_type;
		u32 elem_type_id = array->type;
		u32 elem_size;

		elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
		return elem_type && !btf_type_is_modifier(elem_type) &&
			(array->nelems * elem_size ==
			 btf->resolved_sizes[type_id]);
	}

	return false;
}

static int btf_check_all_types(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	u32 type_id;
	int err;

	err = env_resolve_init(env);
	if (err)
		return err;

	env->phase++;
	for (type_id = 1; type_id <= btf->nr_types; type_id++) {
		const struct btf_type *t = btf_type_by_id(btf, type_id);

		env->log_type_id = type_id;
		if (btf_type_needs_resolve(t) &&
		    !env_type_is_resolved(env, type_id)) {
			err = btf_resolve(env, t, type_id);
			if (err)
				return err;
		}

		if (btf_type_needs_resolve(t) &&
		    !btf_resolve_valid(env, t, type_id)) {
			btf_verifier_log_type(env, t, "Invalid resolve state");
			return -EINVAL;
		}
	}

	return 0;
}

static int btf_parse_type_sec(struct btf_verifier_env *env)
{
	const struct btf_header *hdr = &env->btf->hdr;
	int err;

	/* Type section must align to 4 bytes */
	if (hdr->type_off & (sizeof(u32) - 1)) {
		btf_verifier_log(env, "Unaligned type_off");
		return -EINVAL;
	}

	if (!hdr->type_len) {
		btf_verifier_log(env, "No type found");
		return -EINVAL;
	}

	err = btf_check_all_metas(env);
	if (err)
		return err;

	return btf_check_all_types(env);
}

static int btf_parse_str_sec(struct btf_verifier_env *env)
{
	const struct btf_header *hdr;
	struct btf *btf = env->btf;
	const char *start, *end;

	hdr = &btf->hdr;
	start = btf->nohdr_data + hdr->str_off;
	end = start + hdr->str_len;

	if (end != btf->data + btf->data_size) {
		btf_verifier_log(env, "String section is not at the end");
		return -EINVAL;
	}

	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_NAME_OFFSET ||
	    start[0] || end[-1]) {
		btf_verifier_log(env, "Invalid string section");
		return -EINVAL;
	}

	btf->strings = start;

	return 0;
}

static const size_t btf_sec_info_offset[] = {
	offsetof(struct btf_header, type_off),
	offsetof(struct btf_header, str_off),
};

static int btf_sec_info_cmp(const void *a, const void *b)
{
	const struct btf_sec_info *x = a;
	const struct btf_sec_info *y = b;

	return (int)(x->off - y->off) ? : (int)(x->len - y->len);
}

static int btf_check_sec_info(struct btf_verifier_env *env,
			      u32 btf_data_size)
{
	struct btf_sec_info secs[ARRAY_SIZE(btf_sec_info_offset)];
	u32 total, expected_total, i;
	const struct btf_header *hdr;
	const struct btf *btf;

	btf = env->btf;
	hdr = &btf->hdr;

	/* Populate the secs from hdr */
	for (i = 0; i < ARRAY_SIZE(btf_sec_info_offset); i++)
		secs[i] = *(struct btf_sec_info *)((void *)hdr +
						   btf_sec_info_offset[i]);

	sort(secs, ARRAY_SIZE(btf_sec_info_offset),
	     sizeof(struct btf_sec_info), btf_sec_info_cmp, NULL);

	/* Check for gaps and overlap among sections */
	total = 0;
	expected_total = btf_data_size - hdr->hdr_len;
	for (i = 0; i < ARRAY_SIZE(btf_sec_info_offset); i++) {
		if (expected_total < secs[i].off) {
			btf_verifier_log(env, "Invalid section offset");
			return -EINVAL;
		}
		if (total < secs[i].off) {
			/* gap */
			btf_verifier_log(env, "Unsupported section found");
			return -EINVAL;
		}
		if (total > secs[i].off) {
			btf_verifier_log(env, "Section overlap found");
			return -EINVAL;
		}
		if (expected_total - total < secs[i].len) {
			btf_verifier_log(env,
					 "Total section length too long");
			return -EINVAL;
		}
		total += secs[i].len;
	}

	/* There is data other than hdr and known sections */
	if (expected_total != total) {
		btf_verifier_log(env, "Unsupported section found");
		return -EINVAL;
	}

	return 0;
}

static int btf_parse_hdr(struct btf_verifier_env *env)
{
	u32 hdr_len, hdr_copy, btf_data_size;
	const struct btf_header *hdr;
	struct btf *btf;
	int err;

	btf = env->btf;
	btf_data_size = btf->data_size;

	if (btf_data_size <
	    offsetof(struct btf_header, hdr_len) + sizeof(hdr->hdr_len)) {
		btf_verifier_log(env, "hdr_len not found");
		return -EINVAL;
	}

	hdr = btf->data;
	hdr_len = hdr->hdr_len;
	if (btf_data_size < hdr_len) {
		btf_verifier_log(env, "btf_header not found");
		return -EINVAL;
	}

	/* Ensure the unsupported header fields are zero */
	if (hdr_len > sizeof(btf->hdr)) {
		u8 *expected_zero = btf->data + sizeof(btf->hdr);
		u8 *end = btf->data + hdr_len;

		for (; expected_zero < end; expected_zero++) {
			if (*expected_zero) {
				btf_verifier_log(env, "Unsupported btf_header");
				return -E2BIG;
			}
		}
	}

	hdr_copy = min_t(u32, hdr_len, sizeof(btf->hdr));
	memcpy(&btf->hdr, btf->data, hdr_copy);

	hdr = &btf->hdr;

	btf_verifier_log_hdr(env, btf_data_size);

	if (hdr->magic != BTF_MAGIC) {
		btf_verifier_log(env, "Invalid magic");
		return -EINVAL;
	}

	if (hdr->version != BTF_VERSION) {
		btf_verifier_log(env, "Unsupported version");
		return -ENOTSUPP;
	}

	if (hdr->flags) {
		btf_verifier_log(env, "Unsupported flags");
		return -ENOTSUPP;
	}

	if (btf_data_size == hdr->hdr_len) {
		btf_verifier_log(env, "No data");
		return -EINVAL;
	}

	err = btf_check_sec_info(env, btf_data_size);
	if (err)
		return err;

	return 0;
}

static struct btf *btf_parse(void __user *btf_data, u32 btf_data_size,
			     u32 log_level, char __user *log_ubuf, u32 log_size)
{
	struct btf_verifier_env *env = NULL;
	struct bpf_verifier_log *log;
	struct btf *btf = NULL;
	u8 *data;
	int err;

	if (btf_data_size > BTF_MAX_SIZE)
		return ERR_PTR(-E2BIG);

	env = kzalloc(sizeof(*env), GFP_KERNEL | __GFP_NOWARN);
	if (!env)
		return ERR_PTR(-ENOMEM);

	log = &env->log;
	if (log_level || log_ubuf || log_size) {
		/* user requested verbose verifier output
		 * and supplied buffer to store the verification trace
		 */
		log->level = log_level;
		log->ubuf = log_ubuf;
		log->len_total = log_size;

		/* log attributes have to be sane */
		if (log->len_total < 128 || log->len_total > UINT_MAX >> 8 ||
		    !log->level || !log->ubuf) {
			err = -EINVAL;
			goto errout;
		}
	}

	btf = kzalloc(sizeof(*btf), GFP_KERNEL | __GFP_NOWARN);
	if (!btf) {
		err = -ENOMEM;
		goto errout;
	}
	env->btf = btf;

	data = kvmalloc(btf_data_size, GFP_KERNEL | __GFP_NOWARN);
	if (!data) {
		err = -ENOMEM;
		goto errout;
	}

	btf->data = data;
	btf->data_size = btf_data_size;

	if (copy_from_user(data, btf_data, btf_data_size)) {
		err = -EFAULT;
		goto errout;
	}

	err = btf_parse_hdr(env);
	if (err)
		goto errout;

	btf->nohdr_data = btf->data + btf->hdr.hdr_len;

	err = btf_parse_str_sec(env);
	if (err)
		goto errout;

	err = btf_parse_type_sec(env);
	if (err)
		goto errout;

	if (log->level && bpf_verifier_log_full(log)) {
		err = -ENOSPC;
		goto errout;
	}

	btf_verifier_env_free(env);
	refcount_set(&btf->refcnt, 1);
	return btf;

errout:
	btf_verifier_env_free(env);
	if (btf)
		btf_free(btf);
	return ERR_PTR(err);
}

void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
		       struct seq_file *m)
{
	const struct btf_type *t = btf_type_by_id(btf, type_id);

	btf_type_ops(t)->seq_show(btf, t, type_id, obj, 0, m);
}

static int btf_release(struct inode *inode, struct file *filp)
{
	btf_put(filp->private_data);
	return 0;
}

const struct file_operations btf_fops = {
	.release	= btf_release,
};

static int __btf_new_fd(struct btf *btf)
{
	return anon_inode_getfd("btf", &btf_fops, btf, O_RDONLY | O_CLOEXEC);
}

int btf_new_fd(const union bpf_attr *attr)
{
	struct btf *btf;
	int ret;

	btf = btf_parse(u64_to_user_ptr(attr->btf),
			attr->btf_size, attr->btf_log_level,
			u64_to_user_ptr(attr->btf_log_buf),
			attr->btf_log_size);
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	ret = btf_alloc_id(btf);
	if (ret) {
		btf_free(btf);
		return ret;
	}

	/*
	 * The BTF ID is published to the userspace.
	 * All BTF free must go through call_rcu() from
	 * now on (i.e. free by calling btf_put()).
	 */

	ret = __btf_new_fd(btf);
	if (ret < 0)
		btf_put(btf);

	return ret;
}

struct btf *btf_get_by_fd(int fd)
{
	struct btf *btf;
	struct fd f;

	f = fdget(fd);

	if (!f.file)
		return ERR_PTR(-EBADF);

	if (f.file->f_op != &btf_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	btf = f.file->private_data;
	refcount_inc(&btf->refcnt);
	fdput(f);

	return btf;
}

int btf_get_info_by_fd(const struct btf *btf,
		       const union bpf_attr *attr,
		       union bpf_attr __user *uattr)
{
	struct bpf_btf_info __user *uinfo;
	struct bpf_btf_info info = {};
	u32 info_copy, btf_copy;
	void __user *ubtf;
	u32 uinfo_len;

	uinfo = u64_to_user_ptr(attr->info.info);
	uinfo_len = attr->info.info_len;

	info_copy = min_t(u32, uinfo_len, sizeof(info));
	if (copy_from_user(&info, uinfo, info_copy))
		return -EFAULT;

	info.id = btf->id;
	ubtf = u64_to_user_ptr(info.btf);
	btf_copy = min_t(u32, btf->data_size, info.btf_size);
	if (copy_to_user(ubtf, btf->data, btf_copy))
		return -EFAULT;
	info.btf_size = btf->data_size;

	if (copy_to_user(uinfo, &info, info_copy) ||
	    put_user(info_copy, &uattr->info.info_len))
		return -EFAULT;

	return 0;
}

int btf_get_fd_by_id(u32 id)
{
	struct btf *btf;
	int fd;

	rcu_read_lock();
	btf = idr_find(&btf_idr, id);
	if (!btf || !refcount_inc_not_zero(&btf->refcnt))
		btf = ERR_PTR(-ENOENT);
	rcu_read_unlock();

	if (IS_ERR(btf))
		return PTR_ERR(btf);

	fd = __btf_new_fd(btf);
	if (fd < 0)
		btf_put(btf);

	return fd;
}

u32 btf_id(const struct btf *btf)
{
	return btf->id;
}

#define STACK_CREATE_FLAG_MASK					\
	(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY |	\
	 BPF_F_STACK_BUILD_ID)

struct stack_map_bucket {
	struct pcpu_freelist_node fnode;
	u32 hash;
	u32 nr;
	u64 data[];
};

struct bpf_stack_map {
	struct bpf_map map;
	void *elems;
	struct pcpu_freelist freelist;
	u32 n_buckets;
	struct stack_map_bucket *buckets[];
};

/* irq_work to run up_read() for build_id lookup in nmi context */
struct stack_map_irq_work {
	struct irq_work irq_work;
	struct rw_semaphore *sem;
};

static void do_up_read(struct irq_work *entry)
{
	struct stack_map_irq_work *work;

	work = container_of(entry, struct stack_map_irq_work, irq_work);
	up_read(work->sem);
	work->sem = NULL;
}

static DEFINE_PER_CPU(struct stack_map_irq_work, up_read_work);

static inline bool stack_map_use_build_id(struct bpf_map *map)
{
	return (map->map_flags & BPF_F_STACK_BUILD_ID);
}

static inline int stack_map_data_size(struct bpf_map *map)
{
	return stack_map_use_build_id(map) ?
		sizeof(struct bpf_stack_build_id) : sizeof(u64);
}

static int prealloc_elems_and_freelist(struct bpf_stack_map *smap)
{
	u32 elem_size = sizeof(struct stack_map_bucket) + smap->map.value_size;
	int err;

	smap->elems = bpf_map_area_alloc(elem_size * smap->map.max_entries,
					 smap->map.numa_node);
	if (!smap->elems)
		return -ENOMEM;

	err = pcpu_freelist_init(&smap->freelist);
	if (err)
		goto free_elems;

	pcpu_freelist_populate(&smap->freelist, smap->elems, elem_size,
			       smap->map.max_entries);
	return 0;

free_elems:
	bpf_map_area_free(smap->elems);
	return err;
}

/* Called from syscall */
static struct bpf_map *stack_map_alloc(union bpf_attr *attr)
{
	u32 value_size = attr->value_size;
	struct bpf_stack_map *smap;
	u64 cost, n_buckets;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);

	if (attr->map_flags & ~STACK_CREATE_FLAG_MASK)
		return ERR_PTR(-EINVAL);

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    value_size < 8 || value_size % 8)
		return ERR_PTR(-EINVAL);

	BUILD_BUG_ON(sizeof(struct bpf_stack_build_id) % sizeof(u64));
	if (attr->map_flags & BPF_F_STACK_BUILD_ID) {
		if (value_size % sizeof(struct bpf_stack_build_id) ||
		    value_size / sizeof(struct bpf_stack_build_id)
		    > sysctl_perf_event_max_stack)
			return ERR_PTR(-EINVAL);
	} else if (value_size / 8 > sysctl_perf_event_max_stack)
		return ERR_PTR(-EINVAL);

	/* hash table size must be power of 2 */
	n_buckets = roundup_pow_of_two(attr->max_entries);

	cost = n_buckets * sizeof(struct stack_map_bucket *) + sizeof(*smap);
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-E2BIG);

	smap = bpf_map_area_alloc(cost, bpf_map_attr_numa_node(attr));
	if (!smap)
		return ERR_PTR(-ENOMEM);

	err = -E2BIG;
	cost += n_buckets * (value_size + sizeof(struct stack_map_bucket));
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_smap;

	bpf_map_init_from_attr(&smap->map, attr);
	smap->map.value_size = value_size;
	smap->n_buckets = n_buckets;
	smap->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	err = bpf_map_precharge_memlock(smap->map.pages);
	if (err)
		goto free_smap;

	err = get_callchain_buffers(sysctl_perf_event_max_stack);
	if (err)
		goto free_smap;

	err = prealloc_elems_and_freelist(smap);
	if (err)
		goto put_buffers;

	return &smap->map;

put_buffers:
	put_callchain_buffers();
free_smap:
	bpf_map_area_free(smap);
	return ERR_PTR(err);
}

#define BPF_BUILD_ID 3
/*
 * Parse build id from the note segment. This logic can be shared between
 * 32-bit and 64-bit system, because Elf32_Nhdr and Elf64_Nhdr are
 * identical.
 */
static inline int stack_map_parse_build_id(void *page_addr,
					   unsigned char *build_id,
					   void *note_start,
					   Elf32_Word note_size)
{
	Elf32_Word note_offs = 0, new_offs;

	/* check for overflow */
	if (note_start < page_addr || note_start + note_size < note_start)
		return -EINVAL;

	/* only supports note that fits in the first page */
	if (note_start + note_size > page_addr + PAGE_SIZE)
		return -EINVAL;

	while (note_offs + sizeof(Elf32_Nhdr) < note_size) {
		Elf32_Nhdr *nhdr = (Elf32_Nhdr *)(note_start + note_offs);

		if (nhdr->n_type == BPF_BUILD_ID &&
		    nhdr->n_namesz == sizeof("GNU") &&
		    nhdr->n_descsz == BPF_BUILD_ID_SIZE) {
			memcpy(build_id,
			       note_start + note_offs +
			       ALIGN(sizeof("GNU"), 4) + sizeof(Elf32_Nhdr),
			       BPF_BUILD_ID_SIZE);
			return 0;
		}
		new_offs = note_offs + sizeof(Elf32_Nhdr) +
			ALIGN(nhdr->n_namesz, 4) + ALIGN(nhdr->n_descsz, 4);
		if (new_offs <= note_offs)  /* overflow */
			break;
		note_offs = new_offs;
	}
	return -EINVAL;
}

/* Parse build ID from 32-bit ELF */
static int stack_map_get_build_id_32(void *page_addr,
				     unsigned char *build_id)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)page_addr;
	Elf32_Phdr *phdr;
	int i;

	/* only supports phdr that fits in one page */
	if (ehdr->e_phnum >
	    (PAGE_SIZE - sizeof(Elf32_Ehdr)) / sizeof(Elf32_Phdr))
		return -EINVAL;

	phdr = (Elf32_Phdr *)(page_addr + sizeof(Elf32_Ehdr));

	for (i = 0; i < ehdr->e_phnum; ++i)
		if (phdr[i].p_type == PT_NOTE)
			return stack_map_parse_build_id(page_addr, build_id,
					page_addr + phdr[i].p_offset,
					phdr[i].p_filesz);
	return -EINVAL;
}

/* Parse build ID from 64-bit ELF */
static int stack_map_get_build_id_64(void *page_addr,
				     unsigned char *build_id)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)page_addr;
	Elf64_Phdr *phdr;
	int i;

	/* only supports phdr that fits in one page */
	if (ehdr->e_phnum >
	    (PAGE_SIZE - sizeof(Elf64_Ehdr)) / sizeof(Elf64_Phdr))
		return -EINVAL;

	phdr = (Elf64_Phdr *)(page_addr + sizeof(Elf64_Ehdr));

	for (i = 0; i < ehdr->e_phnum; ++i)
		if (phdr[i].p_type == PT_NOTE)
			return stack_map_parse_build_id(page_addr, build_id,
					page_addr + phdr[i].p_offset,
					phdr[i].p_filesz);
	return -EINVAL;
}

/* Parse build ID of ELF file mapped to vma */
static int stack_map_get_build_id(struct vm_area_struct *vma,
				  unsigned char *build_id)
{
	Elf32_Ehdr *ehdr;
	struct page *page;
	void *page_addr;
	int ret;

	/* only works for page backed storage  */
	if (!vma->vm_file)
		return -EINVAL;

	page = find_get_page(vma->vm_file->f_mapping, 0);
	if (!page)
		return -EFAULT;	/* page not mapped */

	ret = -EINVAL;
	page_addr = page_address(page);
	ehdr = (Elf32_Ehdr *)page_addr;

	/* compare magic x7f "ELF" */
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/* only support executable file and shared object file */
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		goto out;

	if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
		ret = stack_map_get_build_id_32(page_addr, build_id);
	else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
		ret = stack_map_get_build_id_64(page_addr, build_id);
out:
	put_page(page);
	return ret;
}

static void stack_map_get_build_id_offset(struct bpf_stack_build_id *id_offs,
					  u64 *ips, u32 trace_nr, bool user)
{
	int i;
	struct vm_area_struct *vma;
	bool irq_work_busy = false;
	struct stack_map_irq_work *work = NULL;

	if (in_nmi()) {
		work = this_cpu_ptr(&up_read_work);
		if (work->irq_work.flags & IRQ_WORK_BUSY)
			/* cannot queue more up_read, fallback */
			irq_work_busy = true;
	}

	/*
	 * We cannot do up_read() in nmi context. To do build_id lookup
	 * in nmi context, we need to run up_read() in irq_work. We use
	 * a percpu variable to do the irq_work. If the irq_work is
	 * already used by another lookup, we fall back to report ips.
	 *
	 * Same fallback is used for kernel stack (!user) on a stackmap
	 * with build_id.
	 */
	if (!user || !current || !current->mm || irq_work_busy ||
	    down_read_trylock(&current->mm->mmap_sem) == 0) {
		/* cannot access current->mm, fall back to ips */
		for (i = 0; i < trace_nr; i++) {
			id_offs[i].status = BPF_STACK_BUILD_ID_IP;
			id_offs[i].ip = ips[i];
		}
		return;
	}

	for (i = 0; i < trace_nr; i++) {
		vma = find_vma(current->mm, ips[i]);
		if (!vma || stack_map_get_build_id(vma, id_offs[i].build_id)) {
			/* per entry fall back to ips */
			id_offs[i].status = BPF_STACK_BUILD_ID_IP;
			id_offs[i].ip = ips[i];
			continue;
		}
		id_offs[i].offset = (vma->vm_pgoff << PAGE_SHIFT) + ips[i]
			- vma->vm_start;
		id_offs[i].status = BPF_STACK_BUILD_ID_VALID;
	}

	if (!work) {
		up_read(&current->mm->mmap_sem);
	} else {
		work->sem = &current->mm->mmap_sem;
		irq_work_queue(&work->irq_work);
	}
}

BPF_CALL_3(bpf_get_stackid, struct pt_regs *, regs, struct bpf_map *, map,
	   u64, flags)
{
	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
	struct perf_callchain_entry *trace;
	struct stack_map_bucket *bucket, *new_bucket, *old_bucket;
	u32 max_depth = map->value_size / stack_map_data_size(map);
	/* stack_map_alloc() checks that max_depth <= sysctl_perf_event_max_stack */
	u32 init_nr = sysctl_perf_event_max_stack - max_depth;
	u32 skip = flags & BPF_F_SKIP_FIELD_MASK;
	u32 hash, id, trace_nr, trace_len;
	bool user = flags & BPF_F_USER_STACK;
	bool kernel = !user;
	u64 *ips;
	bool hash_matches;

	if (unlikely(flags & ~(BPF_F_SKIP_FIELD_MASK | BPF_F_USER_STACK |
			       BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID)))
		return -EINVAL;

	trace = get_perf_callchain(regs, init_nr, kernel, user,
				   sysctl_perf_event_max_stack, false, false);

	if (unlikely(!trace))
		/* couldn't fetch the stack trace */
		return -EFAULT;

	/* get_perf_callchain() guarantees that trace->nr >= init_nr
	 * and trace-nr <= sysctl_perf_event_max_stack, so trace_nr <= max_depth
	 */
	trace_nr = trace->nr - init_nr;

	if (trace_nr <= skip)
		/* skipping more than usable stack trace */
		return -EFAULT;

	trace_nr -= skip;
	trace_len = trace_nr * sizeof(u64);
	ips = trace->ip + skip + init_nr;
	hash = jhash2((u32 *)ips, trace_len / sizeof(u32), 0);
	id = hash & (smap->n_buckets - 1);
	bucket = READ_ONCE(smap->buckets[id]);

	hash_matches = bucket && bucket->hash == hash;
	/* fast cmp */
	if (hash_matches && flags & BPF_F_FAST_STACK_CMP)
		return id;

	if (stack_map_use_build_id(map)) {
		/* for build_id+offset, pop a bucket before slow cmp */
		new_bucket = (struct stack_map_bucket *)
			pcpu_freelist_pop(&smap->freelist);
		if (unlikely(!new_bucket))
			return -ENOMEM;
		new_bucket->nr = trace_nr;
		stack_map_get_build_id_offset(
			(struct bpf_stack_build_id *)new_bucket->data,
			ips, trace_nr, user);
		trace_len = trace_nr * sizeof(struct bpf_stack_build_id);
		if (hash_matches && bucket->nr == trace_nr &&
		    memcmp(bucket->data, new_bucket->data, trace_len) == 0) {
			pcpu_freelist_push(&smap->freelist, &new_bucket->fnode);
			return id;
		}
		if (bucket && !(flags & BPF_F_REUSE_STACKID)) {
			pcpu_freelist_push(&smap->freelist, &new_bucket->fnode);
			return -EEXIST;
		}
	} else {
		if (hash_matches && bucket->nr == trace_nr &&
		    memcmp(bucket->data, ips, trace_len) == 0)
			return id;
		if (bucket && !(flags & BPF_F_REUSE_STACKID))
			return -EEXIST;

		new_bucket = (struct stack_map_bucket *)
			pcpu_freelist_pop(&smap->freelist);
		if (unlikely(!new_bucket))
			return -ENOMEM;
		memcpy(new_bucket->data, ips, trace_len);
	}

	new_bucket->hash = hash;
	new_bucket->nr = trace_nr;

	old_bucket = xchg(&smap->buckets[id], new_bucket);
	if (old_bucket)
		pcpu_freelist_push(&smap->freelist, &old_bucket->fnode);
	return id;
}

const struct bpf_func_proto bpf_get_stackid_proto = {
	.func		= bpf_get_stackid,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_get_stack, struct pt_regs *, regs, void *, buf, u32, size,
	   u64, flags)
{
	u32 init_nr, trace_nr, copy_len, elem_size, num_elem;
	bool user_build_id = flags & BPF_F_USER_BUILD_ID;
	u32 skip = flags & BPF_F_SKIP_FIELD_MASK;
	bool user = flags & BPF_F_USER_STACK;
	struct perf_callchain_entry *trace;
	bool kernel = !user;
	int err = -EINVAL;
	u64 *ips;

	if (unlikely(flags & ~(BPF_F_SKIP_FIELD_MASK | BPF_F_USER_STACK |
			       BPF_F_USER_BUILD_ID)))
		goto clear;
	if (kernel && user_build_id)
		goto clear;

	elem_size = (user && user_build_id) ? sizeof(struct bpf_stack_build_id)
					    : sizeof(u64);
	if (unlikely(size % elem_size))
		goto clear;

	num_elem = size / elem_size;
	if (sysctl_perf_event_max_stack < num_elem)
		init_nr = 0;
	else
		init_nr = sysctl_perf_event_max_stack - num_elem;
	trace = get_perf_callchain(regs, init_nr, kernel, user,
				   sysctl_perf_event_max_stack, false, false);
	if (unlikely(!trace))
		goto err_fault;

	trace_nr = trace->nr - init_nr;
	if (trace_nr < skip)
		goto err_fault;

	trace_nr -= skip;
	trace_nr = (trace_nr <= num_elem) ? trace_nr : num_elem;
	copy_len = trace_nr * elem_size;
	ips = trace->ip + skip + init_nr;
	if (user && user_build_id)
		stack_map_get_build_id_offset(buf, ips, trace_nr, user);
	else
		memcpy(buf, ips, copy_len);

	if (size > copy_len)
		memset(buf + copy_len, 0, size - copy_len);
	return copy_len;

err_fault:
	err = -EFAULT;
clear:
	memset(buf, 0, size);
	return err;
}

const struct bpf_func_proto bpf_get_stack_proto = {
	.func		= bpf_get_stack,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Called from eBPF program */
static void *stack_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

/* Called from syscall */
int bpf_stackmap_copy(struct bpf_map *map, void *key, void *value)
{
	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
	struct stack_map_bucket *bucket, *old_bucket;
	u32 id = *(u32 *)key, trace_len;

	if (unlikely(id >= smap->n_buckets))
		return -ENOENT;

	bucket = xchg(&smap->buckets[id], NULL);
	if (!bucket)
		return -ENOENT;

	trace_len = bucket->nr * stack_map_data_size(map);
	memcpy(value, bucket->data, trace_len);
	memset(value + trace_len, 0, map->value_size - trace_len);

	old_bucket = xchg(&smap->buckets[id], bucket);
	if (old_bucket)
		pcpu_freelist_push(&smap->freelist, &old_bucket->fnode);
	return 0;
}

static int stack_map_get_next_key(struct bpf_map *map, void *key,
				  void *next_key)
{
	struct bpf_stack_map *smap = container_of(map,
						  struct bpf_stack_map, map);
	u32 id;

	WARN_ON_ONCE(!rcu_read_lock_held());

	if (!key) {
		id = 0;
	} else {
		id = *(u32 *)key;
		if (id >= smap->n_buckets || !smap->buckets[id])
			id = 0;
		else
			id++;
	}

	while (id < smap->n_buckets && !smap->buckets[id])
		id++;

	if (id >= smap->n_buckets)
		return -ENOENT;

	*(u32 *)next_key = id;
	return 0;
}

static int stack_map_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 map_flags)
{
	return -EINVAL;
}

/* Called from syscall or from eBPF program */
static int stack_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);
	struct stack_map_bucket *old_bucket;
	u32 id = *(u32 *)key;

	if (unlikely(id >= smap->n_buckets))
		return -E2BIG;

	old_bucket = xchg(&smap->buckets[id], NULL);
	if (old_bucket) {
		pcpu_freelist_push(&smap->freelist, &old_bucket->fnode);
		return 0;
	} else {
		return -ENOENT;
	}
}

/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
static void stack_map_free(struct bpf_map *map)
{
	struct bpf_stack_map *smap = container_of(map, struct bpf_stack_map, map);

	/* wait for bpf programs to complete before freeing stack map */
	synchronize_rcu();

	bpf_map_area_free(smap->elems);
	pcpu_freelist_destroy(&smap->freelist);
	bpf_map_area_free(smap);
	put_callchain_buffers();
}

const struct bpf_map_ops stack_trace_map_ops = {
	.map_alloc = stack_map_alloc,
	.map_free = stack_map_free,
	.map_get_next_key = stack_map_get_next_key,
	.map_lookup_elem = stack_map_lookup_elem,
	.map_update_elem = stack_map_update_elem,
	.map_delete_elem = stack_map_delete_elem,
	.map_check_btf = map_check_no_btf,
};

static int __init stack_map_init(void)
{
	int cpu;
	struct stack_map_irq_work *work;

	for_each_possible_cpu(cpu) {
		work = per_cpu_ptr(&up_read_work, cpu);
		init_irq_work(&work->irq_work, do_up_read);
	}
	return 0;
}
subsys_initcall(stack_map_init);
