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
    gchar* vlan_s  = g_strdup_printf("%u", start->threadid + 1);
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

static inline int find_thread(void)
{
    for (unsigned int i = 0; i < threads; i++)
    {
        if (g_atomic_int_compare_and_exchange(
                &slots_busy[i],
                0,
                1))
        {
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
        cleanup(start->cloneID, start->threadid+1);

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

    while (!shutting_down)
    {
        

        printf("[%i] Making clone\n", threadid);

        make_clone(xen, &cloneID, threadid + 1, &clone_name);

        if (shutting_down)
        {
            if (cloneID != 0)
                cleanup(cloneID, threadid + 1);

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
            cleanup(cloneID, threadid + 1);

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
    gchar* vlan_s   = g_strdup_printf("%u", start->threadid + 1);
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
        cleanup(start->cloneID, start->threadid+1);

        release_thread(start->threadid);

        g_mutex_clear(&start->timer_lock);
        g_clear_pointer(&start->input, g_free);
        g_clear_pointer(&start->clone_name, g_free);
        g_free(start);
        return;
    } else {
        cleanup(start->cloneID, start->threadid+1);
    }

end:
    if (!shutting_down)
    {
        printf("[%i] %s failed to execute on %u because of a timeout, creating new clone\n", start->threadid, start->input, start->cloneID);
        prepare(start, -1);
        goto restart;
/*
        if (prepared)
        {
            start = prepared;
            goto restart;
        }
*/
    }
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

                    cleanup(_start->cloneID, _start->threadid + 1);
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

    g_atomic_int_set(&slots_busy[threadid], 0);
}

static gboolean valid_threadid(int threadid)
{
    return threadid >= 0 &&
           (guint)threadid < threads;
}