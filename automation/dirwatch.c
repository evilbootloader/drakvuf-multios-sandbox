/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2024 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas@tklengyel.com with any such             *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <glib.h>
/* g_rename() and g_mkdir_with_parents(), which replaced the `mv`
 * subprocess and create the rejected-sample directory (DRAFT-030). */
#include <glib/gstdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/inotify.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
/* open(O_CLOEXEC) and flock() for the host-global VLAN lease (DRAFT-036). */
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <config.h>

#include "../xen_helper/xen_helper.h"

/*
 * The five callback contracts, unchanged in ORDER and ARITY (C9) but no
 * longer built as command strings -- see spawn_argv() below.
 *
 *   clone     <script> <origin> <vlan> <config>
 *   config    <script> <json> <domid> <injpid> <vlan> <run> <file> <out> <utime>
 *   drakvuf   <script> <json> <domid> <injpid> <vlan> <run> <file> <out> <utime>
 *   cleanup   <script> <domid> <vlan>
 *   tcpdump   <script> <vlan> <run> <file> <out> <utime>
 *
 * These used to be g_strdup_printf() templates passed to
 * g_spawn_command_line_sync(), which does NOT run a shell but does apply
 * g_shell_parse_argv() -- shell-style word splitting and quote handling
 * over a string containing an attacker-chosen filename (DRAFT-030).
 * A sample called "a b.exe" split into two arguments and shifted every
 * positional after it, so the worker scripts silently received $RUNFILE
 * and $OUTPUTFOLDER misaligned. An unbalanced quote failed to parse at
 * all. Building argv directly removes the parsing step, and with it the
 * whole class.
 */
#define UNUSED(x) (void)(x)

/*
 * Longest sample filename accepted. Not a security boundary on its own --
 * admission below rejects the dangerous shapes -- but a bound is needed
 * because <in_folder>/<name> must stay inside PATH_MAX and because an
 * absurd name in a log line is its own problem.
 */
#define MAX_SAMPLE_NAME 200

static gboolean valid_threadid(int threadid);

static inline void release_thread(int threadid);

/*
 * Spawns argv directly, with no string-parsing step anywhere in the path.
 * Replaces g_spawn_command_line_sync() at every call site that
 * interpolated a sample filename (DRAFT-030).
 *
 * stdout/stderr are inherited, exactly as before -- the workers' output
 * belongs on dirwatch's console. The one caller that wants stdout is
 * make_clone(), which passes a non-NULL output.
 *
 * Returns TRUE if the child ran and we have its status in *exit_rc.
 */
static gboolean spawn_argv(gchar** argv, gchar** output, gint* exit_rc)
{
    GError* error = NULL;
    gchar* captured = NULL;
    gint status = -1;

    /*
     * G_SPAWN_SEARCH_PATH preserves the previous behaviour exactly:
     * g_spawn_command_line_sync() searched PATH, and dropping that would
     * quietly break any deployment passing a bare script name rather than
     * an absolute path. run_analysis-*.sh passes absolute paths, so this
     * is compatibility, not reliance.
     */
    gboolean ok = g_spawn_sync(NULL,               /* inherit cwd      */
                               argv,
                               NULL,               /* inherit environ  */
                               G_SPAWN_SEARCH_PATH,
                               NULL, NULL,
                               output ? &captured : NULL,
                               NULL,               /* stderr inherited */
                               &status,
                               &error);

    if (!ok)
    {
        fprintf(stderr, "** SPAWN FAILED: %s: %s\n",
                argv[0] ? argv[0] : "(null)",
                error ? error->message : "(no detail)");
        if (error)
            g_error_free(error);
        if (exit_rc)
            *exit_rc = -1;
        return FALSE;
    }

    if (output)
        *output = captured;
    if (exit_rc)
        *exit_rc = status;

    return TRUE;
}

/* Logs the command about to run, without pretending it is a shell line. */
static void print_argv(const char* label, gchar** argv)
{
    printf("** %s:", label);
    for (int i = 0; argv[i]; i++)
        printf(" [%s]", argv[i]);
    printf("\n");
}

/*
 * Admission control at the watch-folder boundary (DRAFT-030, PLAN step 3).
 *
 * REJECT rather than silently normalize, so an operator can see why a
 * sample was not processed. The rules are the Dom0-safety subset of the
 * guest_filename contract in docs/architecture/analysis-pipeline.md,
 * "Filenames: two namespaces": a name that survives this check needs no
 * rewriting, which is what lets the submitted name reach the guest
 * unchanged (C5) without any Dom0 path ever holding an untrusted shape.
 *
 * TWO SHAPES ARE DELIBERATELY ADMITTED, because rejecting them would be a
 * false positive on names an analyst may legitimately receive:
 *
 *   - A LEADING '-'. Every consumer prefixes the folder before the name --
 *     `md5sum -- "$RUNFOLDER/$RUNFILE"` (preconfig-ubuntu.sh:155,
 *     drakvuf-ubuntu.sh:138), `injector -B "$RUNFOLDER/$RUNFILE"` -- so the
 *     argument begins "/malware_processing/..." and the '-' is never in
 *     option position. The prefix is the escape; no quoting is needed. The
 *     `mv` subprocess that DID pass a bare name is gone from this file.
 *   - Windows reserved device names (CON, PRN, trailing dot or space).
 *     Those are hazards in a Windows GUEST, not on Dom0, and dirwatch is
 *     not told which OS it serves. DRAFT-034 owns that check where it can
 *     be applied without rejecting a legitimate Linux sample called
 *     `con.bin`.
 *
 * On rejection, *reason is set to a static string. Never freed.
 */
static gboolean sample_name_admissible(const char* name, const char** reason)
{
    if (!name || !*name)
    {
        *reason = "empty name";
        return FALSE;
    }

    /*
     * "." and ".." are returned by readdir and are not samples. Checked
     * first so the message is accurate rather than blaming the length or
     * character rules below.
     */
    if (!strcmp(name, ".") || !strcmp(name, ".."))
    {
        *reason = "directory entry, not a sample";
        return FALSE;
    }

    if (strlen(name) > MAX_SAMPLE_NAME)
    {
        *reason = "name longer than " G_STRINGIFY(MAX_SAMPLE_NAME) " bytes";
        return FALSE;
    }

    for (const char* p = name; *p; p++)
    {
        /*
         * readdir cannot return a name containing '/' or NUL, so this is
         * belt-and-braces against a future caller rather than a live
         * hazard -- said plainly rather than implied, because a reader
         * checking whether traversal is handled deserves a real answer.
         */
        if (*p == '/')
        {
            *reason = "name contains a path separator";
            return FALSE;
        }

        /*
         * Control characters break every log line and every downstream
         * parser, and a newline in particular lets a name forge log
         * entries. iscntrl over unsigned char: plain char is signed on
         * x86 and a high byte would otherwise index out of range.
         */
        if (iscntrl((unsigned char)*p))
        {
            *reason = "name contains a control character";
            return FALSE;
        }
    }

    return TRUE;
}

struct start_drakvuf
{
    int threadid;
    /*
     * The leased VLAN. Was `threadid + 1` at nine sites until DRAFT-036;
     * it is now whatever the host-global pool handed this worker, so the
     * two numbers are unrelated and the slot index must never be used as
     * a network identity again.
     */
    int vlan;
    /*
     * Clone lifecycles this ONE submission has consumed. The state model's
     * `attempt` field: a timed-out sample is retried on a fresh clone, and
     * neither superseded model could tell a retry from a first run.
     */
    unsigned int attempt;
    domid_t cloneID;
    char* input;
    char* clone_name;
    GMutex timer_lock;
    uint32_t timer;
    time_t utime;
};

static GThreadPool* pool;
static const char* domain_name;
static const char* domain_config;
static const char* json_kernel_path;
static const char* in_folder;
static const char* run_folder;
static const char* out_folder;
static const char* clone_script;
static const char* config_script;
static const char* drakvuf_script;
static const char* cleanup_script;
static const char* tcpdump_script;
static uint32_t threads;
static uint32_t injection_pid;
static bool shutting_down;

static gint slots_busy[128] = { 0 };

xen_interface_t* xen;

void close_handler(int signal)
{
    printf("** SHUTTING DOWN **\n");
    shutting_down = signal;
}

static void
make_clone(xen_interface_t* xen, domid_t* cloneID, uint16_t vlan, char** clone_name)
{
    gchar* vlan_s = g_strdup_printf("%u", vlan);
    gchar* argv[] = {
        (gchar*)clone_script,
        (gchar*)domain_name,
        vlan_s,
        (gchar*)domain_config,
        NULL
    };

    print_argv("RUNNING CLONE", argv);

    /*
     * stdout is captured because it carries the clone's domain id and is
     * the ONLY channel clone.pl has to report success: the exit status is
     * discarded here (see below) and stderr is inherited, so a failed
     * clone is signalled by printing no id at all. clone.pl documents the
     * same contract from its side.
     *
     * KNOWN GAP (DRAFT-010): the exit status is still not read. Passing
     * NULL for exit_rc keeps today's behaviour exactly -- prepare() retries
     * when no id comes back -- rather than changing the retry semantics
     * inside a change about argument parsing.
     */
    char* output = NULL;
    if (spawn_argv(argv, &output, NULL))
        xen_get_dom_info(xen, output, cloneID, clone_name);

    g_free(output);
    g_free(vlan_s);
}

gpointer tcpdump(gpointer data)
{
    struct start_drakvuf* start = (struct start_drakvuf*)data;
    gchar* vlan_s  = g_strdup_printf("%d", start->vlan);
    gchar* utime_s = g_strdup_printf("%lu", (unsigned long)start->utime);
    gchar* argv[] = {
        (gchar*)tcpdump_script,
        vlan_s,
        (gchar*)run_folder,
        start->input,          /* untrusted, and now its own argv element */
        (gchar*)out_folder,
        utime_s,
        NULL
    };

    print_argv("RUNNING TCPDUMP", argv);
    spawn_argv(argv, NULL, NULL);

    g_free(vlan_s);
    g_free(utime_s);
    return NULL;
}

/*
 * ---- Host-global VLAN lease (DRAFT-036) --------------------------------
 *
 * The slot index USED to be the VLAN: slot 0 meant VLAN 1, xenbr1.1 and
 * 172.16.1.0/24. slots_busy[] is process-local, so a second dirwatch
 * handed out VLAN 1 too, and two clones from different pipelines landed on
 * one segment sharing an address, with no rule between them and no symptom
 * in any log. The VLAN is now leased from a host-global pool instead, and
 * the slot index means only "which worker".
 *
 * The authority is the filesystem, not this process: one file per VLAN
 * under $DRAKVUF_LEASE_DIR, held with flock(LOCK_EX|LOCK_NB) for the
 * lifetime of the run. That choice is deliberate over an in-process
 * allocator, because it is what makes the mechanism survive DRAFT-010 --
 * a Python rewrite of dirwatch speaks the same protocol without sharing
 * any code with this file.
 *
 * flock IS the mutual exclusion, and no outer allocation lock is needed
 * around the scan. Two processes may hold open descriptors on the same
 * lease file at once -- open() is not exclusive and is not meant to be --
 * but the kernel grants the lock to exactly one, and the loser moves to
 * the next VLAN. Verified by standalone harness (dirwatch.c cannot be
 * compiled outside a DRAKVUF tree): 64 processes racing for 8 VLANs, 25
 * iterations, 1600 acquisitions, zero duplicates.
 *
 * Crash safety is the kernel's, not ours: the lock is released when the
 * descriptor closes, including when a SIGKILLed process has it closed for
 * it. A watcher killed mid-run strands its clone and its LV -- both known
 * gaps -- but not its VLAN.
 *
 * TWO RULES BELOW ARE LOAD-BEARING, and both were confirmed by removing
 * them in the same harness rather than reasoned about:
 *
 *   1. The lease file is NEVER unlinked. Release is close(), not remove().
 *      Unlinking while another process holds a descriptor on that path
 *      lets a third create a fresh inode there and lock it -- two winners
 *      on one VLAN, with neither call returning an error.
 *
 *   2. O_CLOEXEC is required, not hygiene. flock belongs to the open file
 *      DESCRIPTION, so a descriptor inherited across fork/exec keeps the
 *      lock alive after this process closes its copy. dirwatch spawns
 *      tcpdump for the whole trace; without O_CLOEXEC that child pins the
 *      VLAN after the run released it.
 *
 * The pool is $DRAKVUF_TOTAL_VLANS, exported by run_analysis-<os>.sh from
 * platform.env. It defaults to `threads`, which reproduces today's
 * behaviour exactly for a single watcher, so an un-updated launcher does
 * not break.
 */
#define VLAN_LEASE_DIR_DEFAULT "/run/drakvuf/vlan"

static uint32_t total_vlans;
static int slot_lease_fd[128];
static int slot_vlan[128];

static const char* vlan_lease_dir(void)
{
    const char* d = g_getenv("DRAKVUF_LEASE_DIR");
    return (d && *d) ? d : VLAN_LEASE_DIR_DEFAULT;
}

/*
 * A lease says nothing about whether the network exists. network-setup.sh
 * provisions <bridge>.<vlan> and its gateway from its own argument, so a
 * pool larger than what was provisioned hands out a VLAN with no
 * sub-interface, no gateway and -- because every isolation rule matches
 * the `<bridge>.+` wildcard -- no containment either. That is the same
 * class of silent failure this whole issue exists to remove, so it is
 * checked rather than assumed.
 */
static gboolean vlan_iface_exists(int vlan)
{
    const char* bridge = g_getenv("DRAKVUF_ANALYSIS_BRIDGE");
    if (!bridge || !*bridge)
        bridge = "xenbr1";

    gchar* p = g_strdup_printf("/sys/class/net/%s.%d", bridge, vlan);
    gboolean ok = g_file_test(p, G_FILE_TEST_EXISTS);
    g_free(p);

    return ok;
}

static int vlan_lease_acquire(int* out_vlan)
{
    const char* dir = vlan_lease_dir();

    if (g_mkdir_with_parents(dir, 0700) != 0)
    {
        fprintf(stderr, "[!] Cannot create VLAN lease directory %s: %s\n",
                dir, g_strerror(errno));
        return -1;
    }

    for (uint32_t v = 1; v <= total_vlans; v++)
    {
        gchar* path = g_strdup_printf("%s/%u.lease", dir, v);
        int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        g_free(path);

        if (fd < 0)
            continue;

        if (flock(fd, LOCK_EX | LOCK_NB) != 0)
        {
            close(fd);
            continue;
        }

        if (!vlan_iface_exists((int)v))
        {
            fprintf(stderr,
                    "[!] Leased VLAN %u but its sub-interface does not exist. "
                    "DRAKVUF_TOTAL_VLANS (%u) is larger than what "
                    "network-setup.sh provisioned; a clone here would have no "
                    "gateway and no isolation rules.\n",
                    v, total_vlans);
            close(fd);
            return -1;
        }

        /*
         * Diagnostics only -- nothing reads this back to make a decision.
         * Written under the lock, so it cannot interleave with a second
         * writer, and truncated first so a shorter line cannot leave a
         * previous holder's tail behind.
         */
        gchar* who = g_strdup_printf("pid=%ld domain=%s acquired=%lld\n",
                                     (long)getpid(),
                                     domain_name ? domain_name : "?",
                                     (long long)time(NULL));
        if (ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0)
        {
            ssize_t ignored = write(fd, who, strlen(who));
            (void)ignored;
        }
        g_free(who);

        *out_vlan = (int)v;
        return fd;
    }

    return -1;
}

/*
 * ---- Memory admission (DRAFT-036, second half) -------------------------
 *
 * A clone is created when the host can afford THAT clone, not when a
 * per-watcher counter says so. The counter cannot work across pipelines:
 * three watchers with independent caps either overcommit when all three
 * are busy or leave the host idle when only one is, and they cannot lend
 * capacity because they cannot see each other.
 *
 * Clones are also unequal, which is what makes the count the wrong unit
 * rather than merely a coarse one. Measured on Dom0 2026-08-18:
 *
 *     Ubuntu / Android   cfg 2048 MiB  ->  2160 MiB actually consumed
 *     Windows            cfg 6144 MiB  ->  6256 MiB (projected, DRAFT-034)
 *
 * required = <cfg memory> + DOMAIN_OVERHEAD_MIB, and that is a real bound
 * rather than an estimate: `xl list -l` reports max_memkb equal to the
 * .cfg's memory, so a clone cannot grow into memory admitted to another.
 *
 * THE CHECK IS SERIALIZED, because it is check-then-act and every watcher
 * racing is the NORMAL case rather than the unlucky one. Without the lock
 * each reads the same free_memory, each sees room for one clone, and all
 * proceed -- the host is overcommitted by however many were deciding at
 * that instant, and it surfaces late and badly as a failed or OOM-killed
 * `xl restore` partway through a run rather than as a refused admission.
 *
 * A LOCK ALONE IS NOT ENOUGH, and this is the subtle half. A clone's
 * memory is not accounted by `xl info` until its domain is built, so a
 * lock released when `xl restore` starts leaves the next watcher reading a
 * free_memory that still counts the in-flight clone as free. The
 * reservation therefore outlives the lock: it is written into the VLAN
 * lease file, which this worker already holds for the run, and subtracted
 * from free_memory by every later check until the domain exists.
 *
 * Reusing the lease file rather than adding a second file is deliberate.
 * DRAFT-036 argues VLAN leases and memory reservations should be one
 * mechanism; they have one lifetime and one owner, and a separate
 * reservation file would be a second thing to leak. Crash safety comes
 * free with it -- flock drops when the process dies, so a watcher killed
 * between reserving and building stops being counted without anyone
 * reclaiming anything.
 *
 * The lock is held across read-available -> write-reservation only, and
 * released before `xl restore`. Watchers serialize on the decision, which
 * is milliseconds, not on the clone, which is seconds.
 */

/*
 * Per-domain overhead above the .cfg's `memory`, in MiB.
 *
 * MEASURED at 112: a clone configured for 2048 MiB consumed 2160 MiB of
 * free_memory, against a baseline `xl list` proved empty (Dom0,
 * 2026-08-18). The absolute capacity that follows from that is a property
 * of the host and changes with it; the overhead is a property of Xen and
 * the domain config and does not.
 *
 * SET DELIBERATELY HIGHER THAN MEASURED, and the gap is the point. 112 is
 * one measurement of one Android clone; over-reserving costs a little
 * idle memory, while under-reserving costs a failed or OOM-killed
 * `xl restore` partway through an analysis. The margin is not a guess
 * standing in for a measurement -- it is a margin on top of one.
 *
 * Re-measure per OS rather than assuming this transfers: Windows clones
 * are ~3x larger (DRAFT-034) and their overhead has never been observed.
 */
#define DOMAIN_OVERHEAD_MIB 150

/*
 * Left for Xen's own allocation. NOT for a restore burst: free_memory was
 * sampled at 0.1s across a full clone creation and falls in a monotonic
 * ramp (~220 MiB per sample, about a second) that never dips below its
 * settled value, so there is no transient to absorb.
 */
#define MEM_RESERVE_MIB_DEFAULT 512

static uint32_t clone_memory_mib;
static uint32_t mem_reserve_mib;

/*
 * Clone lifecycles one submission may consume before it is abandoned.
 *
 * Three, not one: a timeout is not always the sample's fault -- a clone
 * can fail to boot, or lose a race with a slow restore -- and the retry
 * exists because those are real. What it must not do is run forever.
 */
#define MAX_ATTEMPTS_DEFAULT 3
static uint32_t max_attempts;

/*
 * Dom0's view of free memory, in MiB, from `xl info`.
 *
 * A subprocess per admission decision, which is once per sample rather
 * than in any loop. Parsed from `xl info` rather than read through
 * xen_helper because this file must not invent an API it cannot check
 * (CLAUDE.md), and `xl info`'s output is already evidenced on Dom0.
 *
 * Returns -1 when the value cannot be read, which callers treat as
 * "refuse admission" rather than "assume plenty".
 */
static long xl_free_memory_mib(void)
{
    gchar* argv[] = { (gchar*)"xl", (gchar*)"info", NULL };
    char* output = NULL;
    long mib = -1;

    if (!spawn_argv(argv, &output, NULL) || !output)
    {
        g_free(output);
        return -1;
    }

    /* free_memory            : 8026 */
    char* p = strstr(output, "free_memory");
    if (p)
    {
        p = strchr(p, ':');
        if (p)
            mib = strtol(p + 1, NULL, 10);
    }

    g_free(output);
    return mib;
}

/*
 * Sum of memory reserved by clones that are not yet built anywhere on this
 * host, including this process's own.
 *
 * A reservation is "live" exactly when its lease is still held, which is
 * tested by trying to take the lock: failure means an owner exists,
 * success means the owner is gone and the file is stale. That is the same
 * test the VLAN pool uses, and it is why a crashed watcher's reservation
 * needs no reclaiming.
 *
 * A second open() of a file this process already locks IS denied by our
 * own lock -- flock treats descriptors independently -- so this counts
 * our own reservation alongside everyone else's. That does not distort
 * the check: the caller clears its reservation to 0 as soon as its domain
 * is built, so at the moment a decision is taken this worker's own entry
 * contributes nothing.
 *
 * Measured, because the alternative would be a silent bug rather than a
 * wrong number: opening and closing that second descriptor does NOT
 * release the lease held on the first. If it did, scanning would drop
 * this worker's own VLAN mid-run and another watcher could take it.
 */
static long outstanding_reservations_mib(void)
{
    const char* dir = vlan_lease_dir();
    long total = 0;

    for (uint32_t v = 1; v <= total_vlans; v++)
    {
        gchar* path = g_strdup_printf("%s/%u.lease", dir, v);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        g_free(path);

        if (fd < 0)
            continue;

        if (flock(fd, LOCK_EX | LOCK_NB) == 0)
        {
            /* Nobody holds it: stale contents, not a live reservation. */
            flock(fd, LOCK_UN);
            close(fd);
            continue;
        }

        char buf[256] = { 0 };
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);

        if (n <= 0)
            continue;

        char* m = strstr(buf, "mem_mib=");
        if (m)
            total += strtol(m + 8, NULL, 10);
    }

    return total;
}

/*
 * Record this worker's reservation into the VLAN lease it already holds.
 * mib of 0 clears it, which is what happens once the domain is built and
 * Xen accounts for the memory itself -- leaving it set would double-count
 * every running clone and shrink apparent capacity permanently.
 */
static void write_reservation(int threadid, long mib)
{
    int fd = slot_lease_fd[threadid];
    if (fd < 0)
        return;

    gchar* s = g_strdup_printf("pid=%ld domain=%s vlan=%d mem_mib=%ld\n",
                               (long)getpid(),
                               domain_name ? domain_name : "?",
                               slot_vlan[threadid],
                               mib);

    if (ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0)
    {
        ssize_t ignored = write(fd, s, strlen(s));
        (void)ignored;
    }

    g_free(s);
}

/*
 * One admission attempt. TRUE means the reservation is recorded and the
 * caller may build its clone; FALSE means the host cannot currently afford
 * it and the caller should wait.
 *
 * Never blocks on the clone, only on the decision.
 */
static gboolean admission_try_reserve(int threadid)
{
    /*
     * Admission disabled: no configured clone size to check against, so
     * admit unconditionally and behave exactly as this file did before
     * DRAFT-036. Deliberately not a refusal -- an un-updated launcher must
     * keep working rather than deadlock on a variable it does not set.
     */
    if (clone_memory_mib == 0)
        return TRUE;

    const char* dir = vlan_lease_dir();
    long required = (long)clone_memory_mib + DOMAIN_OVERHEAD_MIB;
    gboolean admitted = FALSE;

    gchar* lock_path = g_strdup_printf("%s/admission.lock", dir);
    int lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    g_free(lock_path);

    if (lock_fd < 0)
    {
        fprintf(stderr, "[!] Cannot open admission lock: %s\n",
                g_strerror(errno));
        return FALSE;
    }

    /*
     * Blocking, not LOCK_NB: contention here is the expected case with
     * several watchers and the critical section is two reads and a write.
     * Spinning would turn a queue into a race.
     */
    if (flock(lock_fd, LOCK_EX) != 0)
    {
        close(lock_fd);
        return FALSE;
    }

    long free_mib = xl_free_memory_mib();
    if (free_mib >= 0)
    {
        long available = free_mib
                         - outstanding_reservations_mib()
                         - (long)mem_reserve_mib;

        if (required <= available)
        {
            write_reservation(threadid, required);
            admitted = TRUE;
        }
        else
        {
            printf("[%i] Holding: need %ld MiB, %ld available "
                   "(free %ld, reserved elsewhere %ld, host reserve %u)\n",
                   threadid, required, available, free_mib,
                   free_mib - available - (long)mem_reserve_mib,
                   mem_reserve_mib);
        }
    }
    else
    {
        fprintf(stderr, "[%i] Could not read free memory from `xl info`; "
                "refusing admission rather than assuming capacity\n",
                threadid);
    }

    flock(lock_fd, LOCK_UN);
    close(lock_fd);

    return admitted;
}

/*
 * Claims a worker slot AND the VLAN that run will use. The two are
 * acquired together because they have one lifetime: every existing
 * release_thread() call site is also the point at which the VLAN stops
 * being needed, and splitting them would create a second lifetime to get
 * wrong.
 *
 * Returns -1 when no worker slot is free OR when the VLAN pool is
 * exhausted. The caller already retries on -1, so pool exhaustion presents
 * as backpressure rather than as a failed analysis -- which is what the
 * state model's `waiting_for_vlan` describes, though nothing emits it yet
 * (DRAFT-011).
 */
static inline int find_thread(void)
{
    for (unsigned int i = 0; i < threads; i++)
    {
        if (g_atomic_int_compare_and_exchange(
                &slots_busy[i],
                0,
                1))
        {
            int vlan = -1;
            int fd = vlan_lease_acquire(&vlan);

            if (fd < 0)
            {
                /*
                 * Give the slot straight back. Holding a worker slot with
                 * no VLAN would shrink capacity for as long as the pool
                 * stayed full, and would do it invisibly.
                 */
                g_atomic_int_set(&slots_busy[i], 0);
                return -1;
            }

            slot_lease_fd[i] = fd;
            slot_vlan[i] = vlan;

            printf("[%u] Leased VLAN %d\n", i, vlan);
            return (int)i;
        }
    }

    return -1;
}

static inline void cleanup(domid_t cloneID, int vlan)
{
    /*
     * No untrusted input reaches this one -- both values are numeric --
     * but it is converted with the rest so that no g_spawn_command_line_*
     * call survives in this file. A single remaining string-parsed spawn
     * is an invitation to add a %s to it later.
     */
    gchar* domid_s = g_strdup_printf("%u", cloneID);
    gchar* vlan_s  = g_strdup_printf("%u", vlan);
    gchar* argv[] = {
        (gchar*)cleanup_script,
        domid_s,
        vlan_s,
        NULL
    };

    print_argv("RUNNING CLEANUP", argv);
    spawn_argv(argv, NULL, NULL);

    g_free(domid_s);
    g_free(vlan_s);
}

gpointer timer_thread(gpointer data)
{

    struct start_drakvuf* start = (struct start_drakvuf*)data;

    gboolean gotlock = FALSE;

    while (start->timer > 0)
    {
        gotlock = g_mutex_trylock(&start->timer_lock);
        if ( gotlock )
        {
            g_mutex_unlock(&start->timer_lock);
            break;
        }

        start->timer--;
        sleep(1);
    }

    if ( !gotlock )
        cleanup(start->cloneID, start->vlan);

    return NULL;
}

static struct start_drakvuf* prepare(struct start_drakvuf* start, int requested_threadid)
{
    gboolean allocated_here = FALSE;

    if (shutting_down)
        return NULL;

    domid_t cloneID = 0;
    char* clone_name = NULL;
    int threadid = start ? start->threadid : requested_threadid;

    if (!valid_threadid(threadid))
    {
        fprintf(stderr, "[!] Refusing to create clone with invalid thread ID %d (threads=%u)\n", threadid, threads);

        return NULL;
    }

    /*
     * Allocate the worker structure before trying to store clone data in it.
     */
    if (!start)
    {
        start = g_try_malloc0(sizeof(*start));

        if (!start)
        {
            fprintf(stderr, "[%i] Failed to allocate start_drakvuf\n", threadid);
            return NULL;
        }

        allocated_here = TRUE;
        start->threadid = threadid;
        g_mutex_init(&start->timer_lock);
    }
    else
    {
        /*
         * Retrying with the same worker structure.
         * The timed-out clone has already been destroyed by timer_thread().
         */
        start->cloneID = 0;
        g_clear_pointer(&start->clone_name, g_free);
    }

    /*
     * The VLAN comes from the lease find_thread() took alongside this
     * slot, NOT from the slot index -- that equivalence is what DRAFT-036
     * removed. Re-read on the retry path too: the lease is held across a
     * retry (the worker still owns that VLAN), so this is the same value,
     * and reading it in one place keeps it that way if it ever stops being.
     */
    start->vlan = slot_vlan[threadid];

    if (start->vlan < 1)
    {
        fprintf(stderr,
                "[%i] No VLAN leased for this worker slot; refusing to clone. "
                "This is a bug -- find_thread() must not hand out a slot "
                "without one.\n", threadid);

        if (allocated_here)
        {
            g_mutex_clear(&start->timer_lock);
            g_free(start);
        }

        return NULL;
    }

    while (!shutting_down)
    {
        /*
         * Wait for the host to be able to afford this clone before asking
         * Xen for it. The reservation taken here is subtracted from
         * free_memory by every other watcher's check until the domain is
         * built, which is what stops several watchers admitting against
         * the same memory.
         *
         * KNOWN GAP (DRAFT-036, PLAN step 5): this is greedy, and greedy
         * admission starves the LARGEST clone. A Windows job needing ~6.3
         * GiB waits for a window that never opens while smaller Ubuntu and
         * Android jobs keep fitting into memory as it frees. Every
         * individual decision here is correct and the aggregate is not.
         * Head-of-line reservation is the fix and is not implemented; the
         * queue that would order it does not exist yet either.
         */
        while (!shutting_down && !admission_try_reserve(threadid))
            g_usleep(G_USEC_PER_SEC);

        if (shutting_down)
            break;

        printf("[%i] Making clone\n", threadid);

        make_clone(xen, &cloneID, start->vlan, &clone_name);

        /*
         * The domain now exists, so Xen accounts for its memory in
         * `xl info` and the reservation must go: counting both would
         * double-charge every running clone and shrink apparent capacity
         * for as long as it ran. Cleared on the failure paths below too --
         * a reservation for a clone that was never built is capacity
         * withheld from everyone for nothing.
         */
        write_reservation(threadid, 0);

        if (shutting_down)
        {
            if (cloneID != 0)
                cleanup(cloneID, start->vlan);

            g_clear_pointer(&clone_name, g_free);
            break;
        }

        if (cloneID != 0 && clone_name != NULL)
        {
            start->cloneID = cloneID;
            start->clone_name = clone_name;
            start->utime = time(NULL);

            printf("[%i] Clone %s created with domid %u\n", threadid, start->clone_name, start->cloneID);

            return start;
        }

        printf("[%i] Clone creation failed, cleaning partial clone\n",
               threadid);

        /*
         * A domain may have been created even if its name was not parsed.
         */
        if (cloneID != 0)
            cleanup(cloneID, start->vlan);

        g_clear_pointer(&clone_name, g_free);

        cloneID = 0;
        /*
         * Avoid continuously hammering Xen/LVM on failure.
         */
        g_usleep(G_USEC_PER_SEC);
    }

    /*
     * Only free here when this function allocated the structure.
     * Existing structures are owned by run_drakvuf().
     */
    if (allocated_here)
    {
        g_mutex_clear(&start->timer_lock);
        g_free(start);
    }

    return NULL;
}


static inline void start(struct start_drakvuf* start, char* sample)
{
    if ( shutting_down || !start || !sample )
        return;

    start->input = g_strdup(sample);
    g_thread_pool_push(pool, start, NULL);
}

/*
 * Builds and runs one of the two 8-argument worker callbacks. preconfig
 * and drakvuf take an identical shape (C9), so one builder serves both.
 *
 * They read all eight as of 2026-08-18. utime was passed and ignored
 * until then; it is now half the result-directory name
 * (<sha256>/<utime>-<vlan>), which is why both scripts' arity checks
 * require 8 rather than tolerating 7. Nothing here changed to achieve
 * that -- the argument was always being sent.
 *
 * Everything allocated here is freed before it returns, and that is the
 * reason this is a function rather than two inline blocks: run_drakvuf()
 * uses `goto restart` and `goto end`, so anything allocated in its body
 * would leak on every retry or be jumped over on the timeout path.
 *
 * start->input is the untrusted sample name. It is one argv element and
 * is never concatenated into a string, so a name containing a space or a
 * quote cannot shift $OUTPUTFOLDER into $RUNFILE's position.
 */
static void spawn_worker(const char* label,
                         const char* script,
                         struct start_drakvuf* start,
                         gint* rc)
{
    gchar* domid_s  = g_strdup_printf("%u", start->cloneID);
    gchar* injpid_s = g_strdup_printf("%u", injection_pid);
    gchar* vlan_s   = g_strdup_printf("%d", start->vlan);
    gchar* utime_s  = g_strdup_printf("%lu", (unsigned long)start->utime);

    gchar* argv[] = {
        (gchar*)script,
        (gchar*)json_kernel_path,
        domid_s,
        injpid_s,
        vlan_s,
        (gchar*)run_folder,
        start->input,
        (gchar*)out_folder,
        utime_s,
        NULL
    };

    print_argv(label, argv);
    spawn_argv(argv, NULL, rc);

    g_free(domid_s);
    g_free(injpid_s);
    g_free(vlan_s);
    g_free(utime_s);
}

void run_drakvuf(gpointer data, gpointer user_data)
{
    UNUSED(user_data);
    struct start_drakvuf* start = data;
    gint rc;
    GThread* timer;
    GThread* tcpd;

restart:
    rc = 0;
    printf("[%i] Starting %s on domid %u\n", start->threadid, start->input, start->cloneID);

    start->timer = 60;
    g_mutex_lock(&start->timer_lock);
    timer = g_thread_new("timer", timer_thread, start);

    spawn_worker("RUNNING PRECONFIG", config_script, start, &rc);

    g_mutex_unlock(&start->timer_lock);
    g_thread_join(timer);

    printf("[%i] ** Preconfig finished with RC %i. Timer: %i.\n", start->threadid, rc, start->timer);

    if (!start->timer)
        goto end;

    tcpd = g_thread_new("tcpdump", tcpdump, start);

    start->timer = 180;
    g_mutex_lock(&start->timer_lock);
    timer = g_thread_new("timer", timer_thread, start);

    spawn_worker("RUNNING DRAKVUF", drakvuf_script, start, &rc);

    g_mutex_unlock(&start->timer_lock);
    g_thread_join(timer);
    g_thread_join(tcpd);

    printf("[%i] ** DRAKVUF finished with RC %i. Timer: %i\n", start->threadid, rc, start->timer);

    if (start->timer)
    {
        printf("[%i] Finished processing %s\n", start->threadid, start->input);

        /*
         * Destroy the clone on the SUCCESS path too.
         *
         * cleanup() used to be called only in the timeout branch below, so
         * an analysis that completed normally left its clone RUNNING. It
         * was torn down lazily instead -- by clone.pl, on the next sample
         * that happened to take the same VLAN slot, which does `xl domid`
         * and then `xl destroy` before reusing the name. That made the leak
         * invisible on a busy queue and permanent on a quiet one.
         *
         * It is a containment defect rather than untidiness: between the
         * end of the trace and the arrival of the next sample for this
         * slot, the malware keeps executing in a clone that still has
         * NAT'd egress to the Internet (network-setup.sh's DRAKVUF_NAT).
         * On shutdown, every clone stays up.
         *
         * Both dirwatch.c and dirwatch_old.c had this, so it is inherited
         * from the upstream tool rather than introduced by this project.
         *
         * BEFORE release_thread(), not after: the slot index IS the VLAN
         * and the clone name, so releasing first would let another worker
         * claim the slot and start cloning `<origin>-<vlan>-clone` while
         * this domain is still being destroyed.
         *
         * cleanup.sh is idempotent -- `xl pause`/`xl destroy` on a gone
         * domain and `kill` on an empty PID both discard their errors -- so
         * the timeout branch below is unaffected and a double call is safe.
         */
        cleanup(start->cloneID, start->vlan);

        release_thread(start->threadid);

        g_mutex_clear(&start->timer_lock);
        g_clear_pointer(&start->input, g_free);
        g_clear_pointer(&start->clone_name, g_free);
        g_free(start);
        return;
    } else {
        cleanup(start->cloneID, start->vlan);
    }

end:
    /*
     * Every exit from here must release the worker slot and free the
     * structure. Previously only the success path above did: on shutdown
     * this function simply returned, leaking the slot, its VLAN lease and
     * the start_drakvuf (DRAFT-010's finding). With memory admission that
     * leak also withholds a reservation, so it is closed here rather than
     * left beside new code that would inherit it.
     */
    if (shutting_down)
    {
        release_thread(start->threadid);
        g_mutex_clear(&start->timer_lock);
        g_clear_pointer(&start->input, g_free);
        g_clear_pointer(&start->clone_name, g_free);
        g_free(start);
        return;
    }

    /*
     * THE RETRY IS NOW BOUNDED. It was not: this branch called prepare()
     * and `goto restart` with no counter and its return value ignored (the
     * `if (prepared)` guard was commented out), so a sample that reliably
     * times out retried forever -- holding a worker slot and a VLAN, and
     * since DRAFT-036's admission, cycling a memory reservation as well.
     * One malformed sample could occupy a slot indefinitely, which is a
     * local denial of service reachable by submitting a file.
     *
     * `attempt` is the state model's field of the same name
     * (analysis-pipeline.md, "Run"), which exists precisely because one
     * submission can legitimately produce several clone lifecycles.
     * Nothing emits it yet -- DRAFT-011 owns that -- but the count is now
     * real rather than notional.
     */
    start->attempt++;

    if (start->attempt >= max_attempts)
    {
        fprintf(stderr,
                "[%i] %s exhausted %u attempts; giving up. The sample stays "
                "in the run folder and is NOT moved to results.\n",
                start->threadid, start->input, max_attempts);

        cleanup(start->cloneID, start->vlan);
        release_thread(start->threadid);
        g_mutex_clear(&start->timer_lock);
        g_clear_pointer(&start->input, g_free);
        g_clear_pointer(&start->clone_name, g_free);
        g_free(start);
        return;
    }

    printf("[%i] %s failed to execute on %u because of a timeout; "
           "attempt %u of %u, creating new clone\n",
           start->threadid, start->input, start->cloneID,
           start->attempt + 1, max_attempts);

    /*
     * prepare()'s result is checked now. It returns NULL without freeing a
     * caller-owned structure, so `start` is still valid here -- but jumping
     * to restart after a failed prepare would run an analysis against a
     * clone that was never created.
     */
    if (!prepare(start, -1))
    {
        fprintf(stderr, "[%i] Could not prepare a replacement clone for %s; "
                "giving up.\n", start->threadid, start->input);

        release_thread(start->threadid);
        g_mutex_clear(&start->timer_lock);
        g_clear_pointer(&start->input, g_free);
        g_clear_pointer(&start->clone_name, g_free);
        g_free(start);
        return;
    }

    goto restart;
}

int main(int argc, char** argv)
{
    DIR* dir;
    struct dirent* ent;
    unsigned int processed = 0;
    unsigned int total_processed = 0;
    int ret = 0;
    struct sigaction act;
    shutting_down = 0;

    fprintf(stderr, "%s %s v%s Copyright (C) 2014-2024 Tamas K Lengyel\n",
        PACKAGE_NAME, argv[0], PACKAGE_VERSION);

    if (argc!=15)
    {
        printf("Not enough arguments: %i!\n", argc);
        printf("%s <loop (0) or poll (1)> <origin domain name> <domain config> <path to kernel json> <injection pid> <watch folder> <serve folder> <output folder> <max clones> <clone_script> <config_script> <drakvuf_script> <cleanup_script> <tcpdump_script>\n", argv[0]);
        return 1;
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    xen_init_interface(&xen);

    int do_poll = atoi(argv[1]);
    domain_name = argv[2];
    domain_config = argv[3];
    json_kernel_path = argv[4];
    injection_pid = atoi(argv[5]);
    in_folder = argv[6];
    run_folder = argv[7];
    out_folder = argv[8];
    threads = atoi(argv[9]);
    clone_script = argv[10];
    config_script = argv[11];
    drakvuf_script = argv[12];
    cleanup_script = argv[13];
    tcpdump_script = argv[14];

    if (threads <= 0 || threads > 128)
    {
        printf("Invalid clone count %u (valid range: 1-128)\n", threads);
        return 1;
    }

    /*
     * Explicitly, and NOT left to static zero-initialization: fd 0 is
     * stdin, so a zeroed slot_lease_fd[] would make release_thread()'s
     * `>= 0` test true for a slot that holds no lease and close stdin.
     */
    for (unsigned int i = 0; i < 128; i++)
    {
        slot_lease_fd[i] = -1;
        slot_vlan[i] = -1;
    }

    /*
     * The VLAN pool is host-global and therefore cannot come from argv --
     * this contract is per-watcher and every launcher passes its own
     * clone count in argv[9]. It arrives in the environment instead,
     * exported by run_analysis-<os>.sh from platform.env, which is the
     * same mechanism clone.pl already takes VG_NAME and CLONE_LV_SIZE
     * through.
     *
     * Defaulting to `threads` reproduces the pre-DRAFT-036 behaviour
     * exactly for a single watcher -- VLANs 1..threads, one per slot -- so
     * a launcher that has not been updated still works and simply cannot
     * run alongside a second one.
     */
    const char* pool_s = g_getenv("DRAKVUF_TOTAL_VLANS");
    total_vlans = (pool_s && *pool_s) ? (uint32_t)atoi(pool_s) : threads;

    if (total_vlans < threads || total_vlans > 254)
    {
        printf("Invalid DRAKVUF_TOTAL_VLANS %u: must be >= this watcher's "
               "clone count (%u) and <= 254 (the VLAN id is the third octet "
               "of the gateway address).\n", total_vlans, threads);
        return 1;
    }

    /*
     * This clone's configured memory, from the same .cfg dirwatch already
     * receives as argv[3]. The launcher greps it and exports it rather
     * than this file parsing Xen config syntax in C: the .cfg stays the
     * single source of truth, nobody types the number twice, and a
     * mismatch between config and admission is impossible by construction.
     *
     * Zero disables memory admission and restores the pre-DRAFT-036
     * behaviour of admitting whatever the worker-slot count allows. That
     * is the safe default for a launcher that has not been updated: it
     * cannot silently admit against a wrong figure, because it does not
     * admit against a figure at all.
     */
    const char* mem_s = g_getenv("DRAKVUF_CLONE_MEMORY_MIB");
    clone_memory_mib = (mem_s && *mem_s) ? (uint32_t)atoi(mem_s) : 0;

    const char* reserve_s = g_getenv("DRAKVUF_MEM_RESERVE_MIB");
    mem_reserve_mib = (reserve_s && *reserve_s)
                      ? (uint32_t)atoi(reserve_s)
                      : MEM_RESERVE_MIB_DEFAULT;

    const char* attempts_s = g_getenv("DRAKVUF_MAX_ATTEMPTS");
    max_attempts = (attempts_s && *attempts_s)
                   ? (uint32_t)atoi(attempts_s)
                   : MAX_ATTEMPTS_DEFAULT;

    if (max_attempts < 1)
        max_attempts = 1;

    printf("VLAN pool: 1..%u (leases in %s), worker slots: %u\n",
           total_vlans, vlan_lease_dir(), threads);

    if (clone_memory_mib > 0)
        printf("Memory admission: %u MiB cfg + %u MiB overhead = %u MiB "
               "per clone, host reserve %u MiB\n",
               clone_memory_mib, DOMAIN_OVERHEAD_MIB,
               clone_memory_mib + DOMAIN_OVERHEAD_MIB, mem_reserve_mib);
    else
        printf("Memory admission: DISABLED (DRAKVUF_CLONE_MEMORY_MIB unset) "
               "-- clones are limited only by worker slots, and concurrent "
               "watchers can overcommit this host\n");

    pool = g_thread_pool_new(run_drakvuf, NULL, threads, TRUE, NULL);

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, in_folder, IN_CLOSE_WRITE);
    char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];

    struct pollfd pollfd =
    {
        .fd = fd,
        .events = POLLIN
    };

    int threadid = -1;

    do
    {
        processed = 0;

        if ((dir = opendir (in_folder)) != NULL)
        {
            while ((ent = readdir (dir)) != NULL && !shutting_down)
            {
                if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                    continue;

                /*
                 * Admission BEFORE a worker slot is claimed and before a
                 * clone is built, so an unprocessable name costs nothing.
                 *
                 * A rejected sample is moved aside rather than left where
                 * it is. Leaving it would spin: the scan re-reads the watch
                 * folder every cycle, so a name that can never be processed
                 * would be re-rejected and re-logged forever (DRAFT-030,
                 * PLAN step 4).
                 */
                const char* reject_reason = NULL;
                if (!sample_name_admissible(ent->d_name, &reject_reason))
                {
                    char* shown = g_strescape(ent->d_name, NULL);

                    /*
                     * A name that is not safe to path-join must not be
                     * path-joined -- not even to move it out of the way.
                     * g_build_filename(in_folder, "../../etc/passwd")
                     * resolves OUTSIDE the watch folder, so the "tidy up"
                     * below would rename a file the check just refused to
                     * accept. readdir cannot return such a name, so this
                     * is unreachable today; it is guarded because the
                     * consequence if it ever became reachable is renaming
                     * an arbitrary file as root.
                     *
                     * These are logged and left alone. They cannot spin
                     * the loop the way an admissible-but-broken name
                     * could, because nothing can create them here.
                     */
                    if (strchr(ent->d_name, '/')
                        || !strcmp(ent->d_name, ".")
                        || !strcmp(ent->d_name, ".."))
                    {
                        fprintf(stderr,
                                "** REJECTED SAMPLE: \"%s\": %s; left in "
                                "place -- the name is not safe to path-join "
                                "and will not be moved\n",
                                shown ? shown : "(unprintable)",
                                reject_reason);
                        g_free(shown);
                        continue;
                    }

                    char* src = g_build_filename(in_folder, ent->d_name, NULL);
                    char* rejected_dir = g_build_filename(out_folder, "rejected", NULL);

                    if (g_mkdir_with_parents(rejected_dir, 0700) != 0)
                        fprintf(stderr,
                                "** REJECTED SAMPLE: cannot create %s (%s)\n",
                                rejected_dir, g_strerror(errno));

                    /*
                     * The destination leaf is the digest of the REJECTED
                     * name, not the name itself -- the name is exactly what
                     * was just judged unfit to appear in a Dom0 path, so
                     * reusing it here would defeat the check. The log line
                     * below carries the original, escaped, so an operator
                     * can still match the two up.
                     */
                    char* leaf = g_compute_checksum_for_string(
                                     G_CHECKSUM_SHA256, ent->d_name, -1);
                    char* dst = g_build_filename(rejected_dir, leaf, NULL);

                    fprintf(stderr,
                            "** REJECTED SAMPLE: \"%s\": %s; moved to %s\n",
                            shown ? shown : "(unprintable)",
                            reject_reason,
                            dst);

                    if (g_rename(src, dst) != 0)
                        fprintf(stderr,
                                "** REJECTED SAMPLE: could not move it aside "
                                "(%s); it will be re-reported next scan\n",
                                g_strerror(errno));

                    g_free(shown);
                    g_free(dst);
                    g_free(leaf);
                    g_free(rejected_dir);
                    g_free(src);
                    continue;
                }

                /*
                 * One worker slot per sample, reserved inside the scan
                 * loop rather than once per directory pass.
                 */
                threadid = -1;
                while (threadid < 0 && !shutting_down)
                {
                    threadid = find_thread();
                    if (threadid < 0)
                        sleep(1);
                }

                if (shutting_down)
                {
                    if (threadid >= 0)
                        release_thread(threadid);
                    threadid = -1;
                    break;
                }

                /*
                 * prepare() retries clone creation until it succeeds or a
                 * shutdown is requested.  Keep the sample in in_folder while
                 * waiting so it cannot be stranded in run_folder.
                 */
                struct start_drakvuf* _start = prepare(NULL, threadid);

                if (!_start)
                {
                    fprintf(stderr, "[%i] Unable to prepare clone for %s; " 
                            "leaving it in the input directory\n",
                            threadid,
                            ent->d_name);

                    release_thread(threadid);
                    threadid = -1;

                    if (!shutting_down)
                        sleep(1);

                    continue;
                }

                /*
                 * Was: g_spawn_command_line_sync("mv %s/%s %s/%s", ...).
                 * Moving a file does not need a subprocess, and building
                 * that command put an attacker-chosen name through
                 * g_shell_parse_argv() -- a space split it into two
                 * arguments and moved the wrong path; an unbalanced quote
                 * failed to parse, leaving the sample in the watch folder
                 * to be retried forever; a leading '-' was read by mv as an
                 * option. rename(2) has none of those properties
                 * (DRAFT-030).
                 *
                 * in_folder and run_folder are documented as top-level
                 * siblings (/malware_incoming/<os>, /malware_processing/<os>),
                 * so this is expected to be a same-filesystem rename. If they
                 * are ever split across mounts, rename() fails with EXDEV and
                 * is reported below rather than silently copying.
                 */
                char* move_src = g_build_filename(in_folder, ent->d_name, NULL);
                char* move_dst = g_build_filename(run_folder, ent->d_name, NULL);

                printf("** MOVING FILE FOR PROCESSING: %s -> %s\n",
                       move_src, move_dst);

                gboolean move_ok = (g_rename(move_src, move_dst) == 0);
                int move_errno = errno;

                g_free(move_src);
                g_free(move_dst);

                if (!move_ok)
                {
                    fprintf(stderr, "[%i] rename failed: %s\n",
                            threadid, g_strerror(move_errno));
                    fprintf(stderr,
                            "[%i] Failed to move %s into the processing "
                            "directory; discarding prepared clone %u\n",
                            threadid,
                            ent->d_name,
                            _start->cloneID);

                    cleanup(_start->cloneID, _start->vlan);
                    g_mutex_clear(&_start->timer_lock);
                    g_clear_pointer(&_start->clone_name, g_free);
                    g_free(_start);

                    release_thread(threadid);
                    threadid = -1;
                    continue;
                }

                start(_start, ent->d_name);

                threadid = -1;
                processed++;
            }
            closedir (dir);
        }
        else
        {
            printf("Failed to open target folder!\n");
            ret = 1;
            break;
        }

        if ( processed )
        {
            total_processed += processed;
            printf("Batch processing started %u samples (total %u)\n", processed, total_processed);
        }

        if ( !processed && !shutting_down )
        {
            if ( do_poll )
            {
                do
                {
                    int rv = poll (&pollfd, 1, 1000);
                    if ( rv < 0 )
                    {
                        printf("Error polling\n");
                        ret = 1;
                        break;
                    }
                    if ( rv > 0 && pollfd.revents & POLLIN )
                    {
                        if ( read( fd, buffer, sizeof(struct inotify_event) + NAME_MAX + 1 ) < 0 )
                        {
                            printf("Error reading inotify event\n");
                            ret = 1;
                        }
                        break;
                    }
                } while (!shutting_down && !ret);
            }
            else
                sleep(1);
        }
    } while (!shutting_down && !ret);

    inotify_rm_watch( fd, wd );
    close(fd);

    g_thread_pool_free(pool, FALSE, TRUE);

    if ( threadid >= 0 )
        release_thread(threadid);

    xen_free_interface(xen);

    printf("Finished processing %u samples\n", total_processed);
    return ret;
}

static inline void release_thread(int threadid)
{
    if (threadid < 0 || (guint)threadid >= threads)
        return;

    /*
     * Release the VLAN before the slot, for the same reason cleanup()
     * runs before release_thread() at :702 -- whatever becomes claimable
     * first must be the thing that is already finished with. Closing the
     * descriptor drops the flock; the file itself is deliberately left in
     * place (see the lease notes above -- unlinking it is a correctness
     * bug, not untidiness).
     */
    if (slot_lease_fd[threadid] >= 0)
    {
        close(slot_lease_fd[threadid]);
        slot_lease_fd[threadid] = -1;
        slot_vlan[threadid] = -1;
    }

    g_atomic_int_set(&slots_busy[threadid], 0);
}

static gboolean valid_threadid(int threadid)
{
    return threadid >= 0 &&
           (guint)threadid < threads;
}