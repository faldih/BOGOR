#include <stdio.h>
#include <stdlib.h>
#include <cstdio>
#include <stdcerr>
#include <vector.h>

unsigned long long __weak sched_clock(void)
{
	return (unsigned long long)(jiffies - INITIAL_JIFFIES)
					* (NSEC_PER_SEC / HZ);
}
EXPORT_SYMBOL_GPL(sched_clock);

static DEFINE_STATIC_KEY_FALSE(sched_clock_running);

#ifdef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
static DEFINE_STATIC_KEY_FALSE(__sched_clock_stable);
static int __sched_clock_stable_early = 1;
__read_mostly u64 __sched_clock_offset;
static __read_mostly u64 __gtod_offset;

struct sched_clock_data {
	u64			tick_raw;
	u64			tick_gtod;
	u64			clock;
};

static DEFINE_PER_CPU_SHARED_ALIGNED(struct sched_clock_data, sched_clock_data);

static inline struct sched_clock_data *this_scd(void)
{
	return this_cpu_ptr(&sched_clock_data);
}

static inline struct sched_clock_data *cpu_sdc(int cpu)
{
	return &per_cpu(sched_clock_data, cpu);
}

int sched_clock_stable(void)
{
	return static_branch_likely(&__sched_clock_stable);
}

static void __scd_stamp(struct sched_clock_data *scd)
{
	scd->tick_gtod = ktime_get_ns();
	scd->tick_raw = sched_clock();
}

static void __set_sched_clock_stable(void)
{
	struct sched_clock_data *scd;

	
	local_irq_disable();
	scd = this_scd();
	__sched_clock_offset = (scd->tick_gtod + __gtod_offset) - (scd->tick_raw);
	local_irq_enable();

	printk(KERN_INFO "sched_clock: Marking stable (%lld, %lld)->(%lld, %lld)\n",
			scd->tick_gtod, __gtod_offset,
			scd->tick_raw,  __sched_clock_offset);

	static_branch_enable(&__sched_clock_stable);
	tick_dep_clear(TICK_DEP_BIT_CLOCK_UNSTABLE);
}

static void __sched_clock_work(struct work_struct *work)
{
	struct sched_clock_data *scd;
	int cpu;
	preempt_disable();
	scd = this_scd();
	__scd_stamp(scd);
	scd->clock = scd->tick_gtod + __gtod_offset;
	preempt_enable();
	for_each_possible_cpu(cpu)
		per_cpu(sched_clock_data, cpu) = *scd;

	printk(KERN_WARNING "TSC found unstable after boot, most likely due to broken BIOS. Use 'tsc=unstable'.\n");
	printk(KERN_INFO "sched_clock: Marking unstable (%lld, %lld)<-(%lld, %lld)\n",
			scd->tick_gtod, __gtod_offset,
			scd->tick_raw,  __sched_clock_offset);

	static_branch_disable(&__sched_clock_stable);
}

static DECLARE_WORK(sched_clock_work, __sched_clock_work);

static void __clear_sched_clock_stable(void)
{
	if (!sched_clock_stable())
		return;

	tick_dep_set(TICK_DEP_BIT_CLOCK_UNSTABLE);
	schedule_work(&sched_clock_work);
}

void clear_sched_clock_stable(void)
{
	__sched_clock_stable_early = 0;

	smp_mb();

	if (static_key_count(&sched_clock_running.key) == 2)
		__clear_sched_clock_stable();
}

static void __sched_clock_gtod_offset(void)
{
	struct sched_clock_data *scd = this_scd();

	__scd_stamp(scd);
	__gtod_offset = (scd->tick_raw + __sched_clock_offset) - scd->tick_gtod;
}

void __init sched_clock_init(void)
{
	local_irq_disable();
	__sched_clock_gtod_offset();
	local_irq_enable();

	static_branch_inc(&sched_clock_running);
}

static int __init sched_clock_init_late(void)
{
	static_branch_inc(&sched_clock_running);
	
	smp_mb(); 

	if (__sched_clock_stable_early)
		__set_sched_clock_stable();

	return 0;
}
late_initcall(sched_clock_init_late);

static inline u64 wrap_min(u64 x, u64 y)
{
	return (s64)(x - y) < 0 ? x : y;
}

static inline u64 wrap_max(u64 x, u64 y)
{
	return (s64)(x - y) > 0 ? x : y;
}
static u64 sched_clock_local(struct sched_clock_data *scd)
{
	u64 now, clock, old_clock, min_clock, max_clock, gtod;
	s64 delta;

again:
	now = sched_clock();
	delta = now - scd->tick_raw;
	if (unlikely(delta < 0))
		delta = 0;

	old_clock = scd->clock;


	gtod = scd->tick_gtod + __gtod_offset;
	clock = gtod + delta;
	min_clock = wrap_max(gtod, old_clock);
	max_clock = wrap_max(old_clock, gtod + TICK_NSEC);

	clock = wrap_max(clock, min_clock);
	clock = wrap_min(clock, max_clock);

	if (cmpxchg64(&scd->clock, old_clock, clock) != old_clock)
		goto again;

	return clock;
}

static u64 sched_clock_remote(struct sched_clock_data *scd)
{
	struct sched_clock_data *my_scd = this_scd();
	u64 this_clock, remote_clock;
	u64 *ptr, old_val, val;

#if BITS_PER_LONG != 64
again:
	this_clock = sched_clock_local(my_scd);
	remote_clock = cmpxchg64(&scd->clock, 0, 0);
#else

	sched_clock_local(my_scd);
again:
	this_clock = my_scd->clock;
	remote_clock = scd->clock;
#endif

	if (likely((s64)(remote_clock - this_clock) < 0)) {
		ptr = &scd->clock;
		old_val = remote_clock;
		val = this_clock;
	} else {
		
		ptr = &my_scd->clock;
		old_val = this_clock;
		val = remote_clock;
	}

	if (cmpxchg64(ptr, old_val, val) != old_val)
		goto again;

	return val;
}

u64 sched_clock_cpu(int cpu)
{
	struct sched_clock_data *scd;
	u64 clock;

	if (sched_clock_stable())
		return sched_clock() + __sched_clock_offset;

	if (!static_branch_unlikely(&sched_clock_running))
		return sched_clock();

	preempt_disable_notrace();
	scd = cpu_sdc(cpu);

	if (cpu != smp_processor_id())
		clock = sched_clock_remote(scd);
	else
		clock = sched_clock_local(scd);
	preempt_enable_notrace();

	return clock;
}
EXPORT_SYMBOL_GPL(sched_clock_cpu);

void sched_clock_tick(void)
{
	struct sched_clock_data *scd;

	if (sched_clock_stable())
		return;

	if (!static_branch_unlikely(&sched_clock_running))
		return;

	lockdep_assert_irqs_disabled();

	scd = this_scd();
	__scd_stamp(scd);
	sched_clock_local(scd);
}

void sched_clock_tick_stable(void)
{
	if (!sched_clock_stable())
		return;
	local_irq_disable();
	__sched_clock_gtod_offset();
	local_irq_enable();
}

void sched_clock_idle_sleep_event(void)
{
	sched_clock_cpu(smp_processor_id());
}
EXPORT_SYMBOL_GPL(sched_clock_idle_sleep_event);

void sched_clock_idle_wakeup_event(void)
{
	unsigned long flags;

	if (sched_clock_stable())
		return;

	if (unlikely(timekeeping_suspended))
		return;

	local_irq_save(flags);
	sched_clock_tick();
	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(sched_clock_idle_wakeup_event);

#else /* CONFIG_HAVE_UNSTABLE_SCHED_CLOCK */

void __init sched_clock_init(void)
{
	static_branch_inc(&sched_clock_running);
	local_irq_disable();
	generic_sched_clock_init();
	local_irq_enable();
}

u64 sched_clock_cpu(int cpu)
{
	if (!static_branch_unlikely(&sched_clock_running))
		return 0;

	return sched_clock();
}

#endif
u64 __weak running_clock(void)
{
	return local_clock();
}
