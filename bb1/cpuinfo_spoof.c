#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cpumask.h>

#include "kirin9020.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cpuinfo_spoof");

extern struct uts_namespace init_uts_ns;

static int spoof_enable = 1;
module_param(spoof_enable, int, 0644);

static unsigned long sym_addr;
static const char *sym_want;

static int __ksym_cb(void *data, const char *name, struct module *mod,
		     unsigned long addr)
{
	(void)data; (void)mod;
	if (sym_want && strcmp(name, sym_want) == 0) {
		sym_addr = addr;
		return 1;
	}
	return 0;
}

static unsigned long ksym_lookup(const char *name)
{
	sym_want = name;
	sym_addr = 0;
#ifdef CONFIG_KALLSYMS
	kallsyms_on_each_symbol(__ksym_cb, NULL);
	if (sym_addr)
		return sym_addr;
#endif
	{
		struct kprobe kp = { .symbol_name = name };
		if (register_kprobe(&kp) == 0) {
			sym_addr = (unsigned long)kp.addr;
			unregister_kprobe(&kp);
		}
	}
	return sym_addr;
}

struct inline_hook {
	unsigned long target;
	void *orig;
	void *trampoline;
};

#define HOOK_STUB_SIZE 16

static int inline_hook_install(struct inline_hook *h, unsigned long target,
			       unsigned long new_fn)
{
	int ret;
	u32 *c;

	h->target = 0;
	h->orig = kmalloc(HOOK_STUB_SIZE, GFP_KERNEL);
	if (!h->orig)
		return -ENOMEM;
	h->trampoline = kmalloc(HOOK_STUB_SIZE, GFP_KERNEL);
	if (!h->trampoline) {
		kfree(h->orig);
		return -ENOMEM;
	}

	memcpy(h->orig, (void *)target, HOOK_STUB_SIZE);

	c = (u32 *)h->trampoline;
	c[0] = 0x58000050;
	c[1] = 0xd61f0200;
	*(u64 *)&c[2] = new_fn;

	ret = set_memory_rw(target & PAGE_MASK, 1);
	if (ret)
		goto out_free;
	memcpy((void *)target, h->trampoline, HOOK_STUB_SIZE);
	flush_icache_range(target, target + HOOK_STUB_SIZE);
	set_memory_ro(target & PAGE_MASK, 1);

	h->target = target;
	return 0;

out_free:
	kfree(h->orig);
	kfree(h->trampoline);
	return ret;
}

static void inline_hook_remove(struct inline_hook *h)
{
	if (!h->target)
		return;
	set_memory_rw(h->target & PAGE_MASK, 1);
	memcpy((void *)h->target, h->orig, HOOK_STUB_SIZE);
	flush_icache_range(h->target, h->target + HOOK_STUB_SIZE);
	set_memory_ro(h->target & PAGE_MASK, 1);
	kfree(h->orig);
	kfree(h->trampoline);
	h->target = 0;
}

static struct inline_hook hook_c_show;
static struct inline_hook hook_online_show;

static int fake_c_show(struct seq_file *m, void *v)
{
	int cpu;

	if (m->index != 0)
		return 0;

	for (cpu = 0; cpu < FAKE_N_CPUS; cpu++) {
		seq_printf(m, "processor\t: %d\n", cpu);
		seq_printf(m, "BogoMIPS\t: %s\n", FAKE_BOGOMIPS);
		seq_printf(m, "Features\t: %s\n", FAKE_FEATURES);
		seq_printf(m, "CPU implementer\t: 0x%x\n", FAKE_IMPLEMENTER);
		seq_printf(m, "CPU architecture: %d\n", FAKE_ARCH);
		seq_printf(m, "CPU variant\t: 0x%x\n", FAKE_VARIANT);
		seq_printf(m, "CPU part\t: 0x%03x\n", fake_cpu_part[cpu]);
		seq_printf(m, "CPU revision\t: %d\n", FAKE_REVISION);
		seq_printf(m, "\n");
	}
	seq_printf(m, "Hardware\t: %s\n", FAKE_HARDWARE);
	return 0;
}

static ssize_t fake_online_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, 64, "0-%d\n", FAKE_N_CPUS - 1);
}

static struct new_utsname saved_uts;

static int uts_spoof_install(void)
{
	memcpy(&saved_uts, &init_uts_ns.name, sizeof(saved_uts));
	strncpy(init_uts_ns.name.release, FAKE_UTS_RELEASE,
		sizeof(init_uts_ns.name.release) - 1);
	strncpy(init_uts_ns.name.version, FAKE_UTS_VERSION,
		sizeof(init_uts_ns.name.version) - 1);
	strncpy(init_uts_ns.name.machine, FAKE_UTS_MACHINE,
		sizeof(init_uts_ns.name.machine) - 1);
	return 0;
}

static void uts_spoof_remove(void)
{
	memcpy(&init_uts_ns.name, &saved_uts, sizeof(saved_uts));
}

static struct kprobe kp_sched_getaffinity;

static void sched_ga_post(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	unsigned long mask_ptr = regs->regs[2];
	unsigned long len = regs->regs[1];
	unsigned long fake_mask;

	if (len < sizeof(fake_mask))
		return;

	fake_mask = (1UL << FAKE_N_CPUS) - 1;
	if (copy_to_user((void __user *)mask_ptr, &fake_mask,
			 sizeof(fake_mask)) == 0)
		regs->regs[0] = sizeof(fake_mask);
}

static int installed = 0;
static struct proc_dir_entry *ctl_entry;

static int do_install(void)
{
	unsigned long a;
	int r;

	if (installed)
		return 0;

	uts_spoof_install();

	a = ksym_lookup("c_show");
	if (a)
		r = inline_hook_install(&hook_c_show, a, (unsigned long)fake_c_show);
	else
		r = -ENOENT;
	if (r)
		pr_warn("cpuinfo_spoof: c_show hook failed %d\n", r);

	a = ksym_lookup("online_show");
	if (a)
		r = inline_hook_install(&hook_online_show, a,
					(unsigned long)fake_online_show);
	else
		r = -ENOENT;
	if (r)
		pr_warn("cpuinfo_spoof: online_show hook failed %d\n", r);

	kp_sched_getaffinity.symbol_name = "__arm64_sys_sched_getaffinity";
	kp_sched_getaffinity.post_handler = sched_ga_post;
	r = register_kprobe(&kp_sched_getaffinity);
	if (r)
		pr_warn("cpuinfo_spoof: sched_getaffinity kprobe failed %d\n", r);

	installed = 1;
	return 0;
}

static void do_remove(void)
{
	if (!installed)
		return;
	if (kp_sched_getaffinity.addr)
		unregister_kprobe(&kp_sched_getaffinity);
	inline_hook_remove(&hook_online_show);
	inline_hook_remove(&hook_c_show);
	uts_spoof_remove();
	installed = 0;
}

static ssize_t ctl_write(struct file *f, const char __user *ubuf, size_t len,
			 loff_t *off)
{
	char buf[16] = {0};
	size_t n = min(len, sizeof(buf) - 1);
	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;

	if (strncmp(buf, "enable", 6) == 0)
		do_install();
	else if (strncmp(buf, "disable", 7) == 0)
		do_remove();
	else
		return -EINVAL;
	return len;
}

static ssize_t ctl_read(struct file *f, char __user *ubuf, size_t len,
			loff_t *off)
{
	char buf[32];
	int n;
	if (*off)
		return 0;
	n = snprintf(buf, sizeof(buf), "spoof=%s\n", installed ? "on" : "off");
	if (copy_to_user(ubuf, buf, n))
		return -EFAULT;
	*off = n;
	return n;
}

static const struct proc_ops ctl_ops = {
	.proc_read = ctl_read,
	.proc_write = ctl_write,
};

static int __init cpuinfo_spoof_init(void)
{
	ctl_entry = proc_create("cpuinfo_spoof", 0644, NULL, &ctl_ops);
	if (!ctl_entry)
		return -ENOMEM;

	if (spoof_enable)
		do_install();

	pr_info("cpuinfo_spoof: loaded, spoof=%s\n", installed ? "on" : "off");
	return 0;
}

static void __exit cpuinfo_spoof_exit(void)
{
	do_remove();
	if (ctl_entry)
		proc_remove(ctl_entry);
	pr_info("cpuinfo_spoof: unloaded\n");
}

module_init(cpuinfo_spoof_init);
module_exit(cpuinfo_spoof_exit);
