#include <asm/unistd.h>
#include <asm/cacheflush.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/pgtable_types.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
MODULE_LICENSE("GPL");

void **system_call_table_addr;

/* my custom syscall that takes process name */
asmlinkage long (*syscall_open) (const char* filename, int flags, umode_t mode);
asmlinkage long (*syscall_write) (unsigned int fd, const char *buff, size_t len);


/* hook */
asmlinkage long hook_open(const char* filename, int flags, umode_t mode)
{
	char buff[100];
	copy_from_user(buff, filename, 100);
	printk(KERN_INFO "Process open-file name:\t%s\n", current->comm);
	printk(KERN_INFO "Filename:\t%s\n", buff);
	return syscall_open(filename, flags, mode);
}

asmlinkage long hook_write(unsigned int fd, const char* buff, size_t len)
{
	printk(KERN_INFO "Process write-file name:\t%s\n", current->comm);
	printk(KERN_INFO "Filename:\t%u, bytes:\t%d\n", fd, (int)len);
	return syscall_write(fd, buff, len);
}

/*Make page writeable*/
int make_rw(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	if(pte->pte & ~_PAGE_RW) {
		pte->pte |= _PAGE_RW;
	}
	return 0;
}

/* Make the page write protected */
int make_ro(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte = pte->pte & ~_PAGE_RW;
	return 0;
}

static int __init entry_point(void)
{
	printk(KERN_INFO "Hook loaded successfully..\n");
	/* my sys_call_table address */
	system_call_table_addr = (void*)0xffffffff81801680;

	/* Replace custom syscall with the correct system call name (write,open,etc) to hook */
	syscall_open = system_call_table_addr[__NR_open];
	syscall_write = system_call_table_addr[__NR_write];

	/* Disable page protection */
	make_rw((unsigned long)system_call_table_addr);

	/* Change syscall to our syscall function */
	system_call_table_addr[__NR_open] = hook_open;
	system_call_table_addr[__NR_write] = hook_write;
	
	return 0;
}

static void __exit exit_point(void)
{
	printk(KERN_INFO "Unloaded Hook successfully\n");
	
	/* Restore original system call */
	system_call_table_addr[__NR_open] = syscall_open;
	system_call_table_addr[__NR_write] = syscall_write;
	
	/* Renable page protection */
	make_ro((unsigned long)system_call_table_addr);
}

module_init(entry_point);
module_exit(exit_point);