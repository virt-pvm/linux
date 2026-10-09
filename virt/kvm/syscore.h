/* SPDX-License-Identifier: GPL-2.0 */
/* Included after the KVM suspend/resume/shutdown callbacks. */
static struct syscore_ops kvm_syscore_ops = {
	.suspend = kvm_suspend,
	.resume = kvm_resume,
	.shutdown = kvm_shutdown,
};

static void kvm_register_syscore(void)
{
	register_syscore_ops(&kvm_syscore_ops);
}

static void kvm_unregister_syscore(void)
{
	unregister_syscore_ops(&kvm_syscore_ops);
}
