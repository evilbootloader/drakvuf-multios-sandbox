/**
 * Sandbox Detection Utility - Stable Version
 * No MAC detection to avoid compilation issues
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <cpuid.h>
#include <sys/ptrace.h>
#include <errno.h>

/* ==================== Configuration ==================== */

#define THRESHOLD_CPU_CORES        2
#define THRESHOLD_RAM_MB         1024
#define THRESHOLD_DISK_GB          40
#define THRESHOLD_UPTIME_MIN       10

/* Verbose output flag */
static bool verbose = false;
static bool json_output = false;
static jmp_buf fault_jmp;

/* Detection result structure */
typedef struct {
    const char *name;
    bool detected;
    double confidence;
    char details[256];
} DetectionResult;

/* Detection results array */
static DetectionResult results[50];
static int result_count = 0;

/* Signal handler for segmentation fault */
void sigsegv_handler(int sig) {
    longjmp(fault_jmp, 1);
}

/* ==================== Helper Functions ==================== */

void add_result(const char *name, bool detected, double confidence, const char *details) {
    if (result_count < 50) {
        results[result_count].name = name;
        results[result_count].detected = detected;
        results[result_count].confidence = confidence;
        strncpy(results[result_count].details, details, 255);
        results[result_count].details[255] = '\0';
        result_count++;
    }
}

void log_info(const char *msg) {
    if (verbose && !json_output) {
        printf("[INFO] %s\n", msg);
    }
}

void log_detection(const char *test, const char *indicator, double confidence) {
    if (!json_output) {
        printf("[DETECT] %s: %s (confidence: %.0f%%)\n", test, indicator, confidence * 100);
    }
}

/* RDTSC for timing */
static inline unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}

/* ==================== CPU / Virtualization Detection ==================== */

/* Check CPUID hypervisor bit */
static bool check_hypervisor_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;
    
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 31)) {
            add_result("CPUID Hypervisor Bit", true, 0.95, "Hypervisor present bit set");
            log_detection("CPUID", "Hypervisor present bit", 0.95);
            return true;
        }
    }
    return false;
}

/* Get hypervisor signature */
static const char* get_hypervisor_signature(void) {
    uint32_t eax, ebx, ecx, edx;
    static char signature[13] = {0};
    
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        memcpy(signature, &ebx, 4);
        memcpy(signature + 4, &ecx, 4);
        memcpy(signature + 8, &edx, 4);
        
        if (strlen(signature) > 0) {
            if (strcmp(signature, "VMwareVMware") == 0) return "VMware";
            if (strcmp(signature, "VBoxVBoxVBox") == 0) return "VirtualBox";
            if (strcmp(signature, "KVMKVMKVM") == 0) return "KVM";
            if (strcmp(signature, "XenVMMXenVMM") == 0) return "Xen";
            if (strcmp(signature, "Microsoft Hv") == 0) return "Hyper-V";
            return signature;
        }
    }
    return NULL;
}

/* Red Pill timing detection */
static bool redpill_timing(void) {
    unsigned long long time1, time2;
    unsigned char idtr[10] = {0};
    
    signal(SIGSEGV, sigsegv_handler);
    if (setjmp(fault_jmp) == 0) {
        __asm__ volatile("sidt %0" : "=m"(idtr));
        time1 = rdtsc();
        __asm__ volatile("sidt %0" : "=m"(idtr));
        time2 = rdtsc();
        printf("Red Pill Timing: (time2 - time1) = %llu\n",time2-time1);
        if (time2 - time1 > 100) {
            add_result("Red Pill Timing", true, 0.70, "SIDT timing anomaly detected");
            log_detection("Red Pill", "SIDT timing anomaly", 0.70);
            signal(SIGSEGV, SIG_DFL);
            return true;
        }
        signal(SIGSEGV, SIG_DFL);
    }
    signal(SIGSEGV, SIG_DFL);
    return false;
}

/* Check for VMware using CPUID */
static bool check_vmware_cpuid(void) {
    uint32_t eax, ebx, ecx, edx;
    
    /* VMware specific check */
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        if (ebx == 0x61774d56) { /* "VMwa" */
            add_result("VMware Detection", true, 0.95, "VMware hypervisor detected");
            log_detection("VMware", "VMware CPUID signature", 0.95);
            return true;
        }
    }
    return false;
}

/* ==================== File Artifact Analysis ==================== */

static bool check_file_content(const char *path, const char *pattern) {
    FILE *fp = fopen(path, "r");
    if (!fp) return false;
    
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, pattern)) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static void check_virtualization_artifacts(void) {
    struct stat st;
    int detected_count = 0;
    char detected_list[256] = {0};
    
    /* VMware artifacts */
    if (stat("/proc/scsi/scsi", &st) == 0 && check_file_content("/proc/scsi/scsi", "VMware")) {
        strcat(detected_list, "VMware SCSI, ");
        detected_count++;
    }
    
    if (stat("/proc/bus/pci/devices", &st) == 0 && check_file_content("/proc/bus/pci/devices", "15ad")) {
        strcat(detected_list, "VMware PCI, ");
        detected_count++;
    }
    
    if (stat("/usr/lib/vmware-tools", &st) == 0 || stat("/usr/bin/vmware-user", &st) == 0) {
        strcat(detected_list, "VMware Tools, ");
        detected_count++;
    }
    
    /* VirtualBox artifacts */
    if (stat("/proc/scsi/scsi", &st) == 0 && check_file_content("/proc/scsi/scsi", "VBOX")) {
        strcat(detected_list, "VirtualBox SCSI, ");
        detected_count++;
    }
    
    if (stat("/opt/VBoxGuestAdditions", &st) == 0) {
        strcat(detected_list, "VirtualBox Guest Additions, ");
        detected_count++;
    }
    
    /* Hyper-V artifacts */
    if (stat("/usr/sbin/hv_kvp_daemon", &st) == 0) {
        strcat(detected_list, "Hyper-V KVP Daemon, ");
        detected_count++;
    }
    
    /* QEMU artifacts */
    if (check_file_content("/proc/cpuinfo", "QEMU")) {
        strcat(detected_list, "QEMU CPU, ");
        detected_count++;
    }
    
    /* Container artifacts */
    if (stat("/.dockerenv", &st) == 0 || stat("/run/.containerenv", &st) == 0) {
        strcat(detected_list, "Container (Docker), ");
        detected_count++;
    }
    
    if (detected_count > 0) {
        detected_list[strlen(detected_list) - 2] = '\0';
        double confidence = 0.70 + (detected_count * 0.05);
        if (confidence > 0.95) confidence = 0.95;
        add_result("Virtualization Artifacts", true, confidence, detected_list);
        log_detection("Artifacts", detected_list, confidence);
    } else {
        add_result("Virtualization Artifacts", false, 0.00, "No virtualization artifacts found");
    }
}

/* ==================== BIOS Validation ==================== */

static void check_bios_info(void) {
    char bios_info[256] = {0};
    int detection_flags = 0;
    struct stat st;
    
    /* Check BIOS vendor */
    if (stat("/sys/class/dmi/id/bios_vendor", &st) == 0) {
        FILE *fp = fopen("/sys/class/dmi/id/bios_vendor", "r");
        if (fp) {
            char vendor[64] = {0};
            if (fgets(vendor, sizeof(vendor), fp)) {
                vendor[strcspn(vendor, "\n")] = 0;
                
                if (strcasestr(vendor, "VMware") || strcasestr(vendor, "VirtualBox") ||
                    strcasestr(vendor, "QEMU") || strcasestr(vendor, "Bochs")) {
                    snprintf(bios_info, sizeof(bios_info), "Virtualized BIOS: %s", vendor);
                    detection_flags++;
                }
            }
            fclose(fp);
        }
    }
    
    /* Check system vendor */
    if (stat("/sys/class/dmi/id/sys_vendor", &st) == 0) {
        FILE *fp = fopen("/sys/class/dmi/id/sys_vendor", "r");
        if (fp) {
            char vendor[64] = {0};
            if (fgets(vendor, sizeof(vendor), fp)) {
                vendor[strcspn(vendor, "\n")] = 0;
                
                if (strcasestr(vendor, "VMware") || strcasestr(vendor, "VirtualBox") ||
                    strcasestr(vendor, "QEMU") || strcasestr(vendor, "KVM")) {
                    snprintf(bios_info, sizeof(bios_info), "Virtualized System: %s", vendor);
                    detection_flags++;
                }
            }
            fclose(fp);
        }
    }
    
    if (detection_flags > 0) {
        double confidence = 0.75 + (detection_flags * 0.10);
        if (confidence > 0.95) confidence = 0.95;
        add_result("BIOS Detection", true, confidence, bios_info);
        log_detection("BIOS", bios_info, confidence);
    } else {
        add_result("BIOS Detection", false, 0.00, "No virtualization in BIOS");
    }
}

/* ==================== Hardware Heuristics ==================== */

static void check_hardware_heuristics(void) {
    int heuristic_score = 0;
    char details[512] = {0};
    int detail_pos = 0;
    
    /* CPU Cores */
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < THRESHOLD_CPU_CORES) {
        heuristic_score++;
        detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
            "Low CPU cores: %ld ", num_cpus);
    } else {
        if (verbose) printf("[INFO] CPU cores: %ld\n", num_cpus);
    }
    
    /* RAM Size */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long long total_ram_mb = (pages * page_size) / (1024 * 1024);
    if (total_ram_mb < THRESHOLD_RAM_MB) {
        heuristic_score++;
        detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
            "Low RAM: %lldMB ", total_ram_mb);
    } else {
        if (verbose) printf("[INFO] RAM: %lld MB\n", total_ram_mb);
    }
    
    /* System Uptime */
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        long uptime_min = info.uptime / 60;
        if (uptime_min < THRESHOLD_UPTIME_MIN) {
            heuristic_score++;
            detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                "Low uptime: %ldmin ", uptime_min);
        } else {
            if (verbose) printf("[INFO] Uptime: %ld minutes\n", uptime_min);
        }
    }
    
    /* Disk Size */
    struct statfs stat_buf;
    if (statfs("/", &stat_buf) == 0) {
        unsigned long long disk_gb = (stat_buf.f_blocks * stat_buf.f_bsize) / (1024ULL * 1024 * 1024);
        if (disk_gb < THRESHOLD_DISK_GB) {
            heuristic_score++;
            detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                "Small disk: %lluGB ", disk_gb);
        } else {
            if (verbose) printf("[INFO] Disk: %llu GB\n", disk_gb);
        }
    }
    
    /* Process Count */
    DIR *proc = opendir("/proc");
    if (proc) {
        int process_count = 0;
        struct dirent *entry;
        while ((entry = readdir(proc)) != NULL) {
            if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                process_count++;
            }
        }
        closedir(proc);
        
        if (process_count < 50) {
            heuristic_score++;
            detail_pos += snprintf(details + detail_pos, sizeof(details) - detail_pos,
                "Low process count: %d ", process_count);
        } else {
            if (verbose) printf("[INFO] Processes: %d\n", process_count);
        }
    }
    
    if (heuristic_score > 0) {
        double confidence = 0.10 + (heuristic_score * 0.10);
        if (confidence > 0.90) confidence = 0.90;
        add_result("Hardware Heuristics", true, confidence, details);
        log_detection("Hardware", details, confidence);
    } else {
        add_result("Hardware Heuristics", false, 0.00, "Normal hardware configuration");
    }
}

/* ==================== Debugger Detection ==================== */

static void check_debugger_detection(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1 && errno != 0) {
        add_result("Debugger Detection", true, 0.85, "Debugger or tracer detected");
        log_detection("Debugger", "ptrace detected", 0.85);
        return;
    }
    add_result("Debugger Detection", false, 0.00, "No debugger detected");
}

/* ==================== Main Function ==================== */

void print_results(void) {
    double total = 0.0;
    int detected_count = 0;
    
    if (json_output) {
        printf("{\n");
        printf("  \"timestamp\": %ld,\n", time(NULL));
        printf("  \"detections\": [\n");
        
        for (int i = 0; i < result_count; i++) {
            printf("    {\n");
            printf("      \"name\": \"%s\",\n", results[i].name);
            printf("      \"detected\": %s,\n", results[i].detected ? "true" : "false");
            printf("      \"confidence\": %.2f,\n", results[i].confidence);
            printf("      \"details\": \"%s\"\n", results[i].details);
            printf("    }%s\n", (i < result_count - 1) ? "," : "");
        }
        
        for (int i = 0; i < result_count; i++) {
            if (results[i].detected) {
                total += results[i].confidence;
                detected_count++;
            }
        }
        double overall = (detected_count > 0) ? (total / detected_count) : 0.0;
        
        printf("  ],\n");
        printf("  \"overall_sandbox_confidence\": %.2f\n", overall);
        printf("}\n");
    } else {
        printf("\n");
        printf("========================================\n");
        printf("   Sandbox Detection Results\n");
        printf("========================================\n\n");
        
        for (int i = 0; i < result_count; i++) {
            const char *status = results[i].detected ? "DETECTED" : "CLEAN";
            printf("[%s] %s\n", status, results[i].name);
            printf("      Confidence: %.0f%%\n", results[i].confidence * 100);
            printf("      Details: %s\n", results[i].details);
            printf("\n");
        }
        
        for (int i = 0; i < result_count; i++) {
            if (results[i].detected) {
                total += results[i].confidence;
                detected_count++;
            }
        }
        double overall = (detected_count > 0) ? (total / detected_count) : 0.0;
        
        printf("========================================\n");
        printf("Overall Confidence: %.0f%%\n", overall * 100);
        printf("========================================\n");
        
        if (overall > 0.70) {
            printf("⚠️  HIGH PROBABILITY: Sandbox/VM detected\n");
        } else if (overall > 0.40) {
            printf("⚠️  MEDIUM PROBABILITY: Possible sandbox\n");
        } else if (overall > 0.10) {
            printf("✓  LOW PROBABILITY: Likely legitimate\n");
        } else {
            printf("✓  CLEAN: No indicators found\n");
        }
    }
}

int main(int argc, char *argv[]) {
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "-j") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Sandbox Detection Utility\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --verbose, -v    Enable verbose output\n");
            printf("  --json, -j       Output in JSON format\n");
            printf("  --help, -h       Show this help\n");
            return 0;
        }
    }
    
    printf("Sandbox Detection Utility v1.0\n");
    printf("================================\n\n");
    
    if (verbose) log_info("Starting detection...");
    
    /* Run detection modules */
    check_hypervisor_cpuid();
    
    const char *hv_sig = get_hypervisor_signature();
    if (hv_sig) {
        add_result("Hypervisor Signature", true, 0.95, hv_sig);
        log_detection("Hypervisor", hv_sig, 0.95);
    } else {
        add_result("Hypervisor Signature", false, 0.00, "No hypervisor detected");
    }
    
    check_vmware_cpuid();
    check_virtualization_artifacts();
    check_bios_info();
    check_hardware_heuristics();
    check_debugger_detection();
    
    print_results();
    
    return redpill_timing();
}
