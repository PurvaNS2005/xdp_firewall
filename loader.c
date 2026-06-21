#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>          // if_nametoindex
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <arpa/inet.h>  // add this to your includes at the top
#include <signal.h>

static volatile int running = 1;

static void handle_signal(int sig) {
    running = 0;
}

static void print_stats(int stats_fd) {
    __u64 total = 0, passed = 0, dropped = 0, rate_limited = 0;

    __u32 key;
    key = 0; bpf_map_lookup_elem(stats_fd, &key, &total);
    key = 1; bpf_map_lookup_elem(stats_fd, &key, &passed);
    key = 2; bpf_map_lookup_elem(stats_fd, &key, &dropped);
    key = 3; bpf_map_lookup_elem(stats_fd, &key, &rate_limited);

    // \r returns cursor to line start so it updates in place
    printf("\r[STATS] total: %llu  passed: %llu  dropped: %llu  rate-limited: %llu    ",
           total, passed, dropped, rate_limited);
    fflush(stdout);  // force immediate output
}

// LPM trie key structure — must match the kernel program
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

// parse "10.0.0.0/24" or "10.0.0.2" into an lpm_key
// returns 0 on success, -1 on failure
static int parse_ip_rule(const char *str, struct lpm_key *key) {
    char ip_str[64];
    int prefix = 32;  // default to exact match

    strncpy(ip_str, str, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    // check for /prefix
    char *slash = strchr(ip_str, '/');
    if (slash) {
        *slash = '\0';            // split string at slash
        prefix = atoi(slash + 1); // parse prefix number
    }

    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0)
        return -1;  // invalid IP

    key->prefixlen = prefix;
    key->addr = addr.s_addr;  // already in network byte order
    return 0;
}

static int load_config(const char *path, int ip_fd, int port_fd, int config_fd) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open config file: %s\n", path);
        return -1;
    }

    char line[256];
    int ip_count = 0, port_count = 0;

    while (fgets(line, sizeof(line), f)) {
        // strip newline
        line[strcspn(line, "\n")] = '\0';

        // skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#')
            continue;

        char keyword[64], value[128];
        if (sscanf(line, "%63s %127s", keyword, value) != 2)
            continue;

        if (strcmp(keyword, "mode") == 0) {
            __u32 key = 0;
            __u32 mode = (strcmp(value, "allowlist") == 0) ? 1 : 0;
            bpf_map_update_elem(config_fd, &key, &mode, BPF_ANY);
            printf("mode set to %s\n", mode ? "allowlist" : "blocklist");

        } else if (strcmp(keyword, "ip") == 0) {
            struct lpm_key key;
            if (parse_ip_rule(value, &key) == 0) {
                __u32 val = 1;
                bpf_map_update_elem(ip_fd, &key, &val, BPF_ANY);
                ip_count++;
            } else {
                fprintf(stderr, "Invalid IP rule: %s\n", value);
            }

        } else if (strcmp(keyword, "port") == 0) {
            __u16 port = (__u16)atoi(value);
            __u32 val = 1;
            bpf_map_update_elem(port_fd, &port, &val, BPF_ANY);
            port_count++;

        } else {
            fprintf(stderr, "Unknown keyword: %s\n", keyword);
        }
    }

    fclose(f);
    printf("Loaded %d IP rules, %d port rules\n", ip_count, port_count);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <config_file>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *config_file = argv[2];

    // get interface index from name (e.g. "veth0" -> 10)
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", ifname);
        return 1;
    }

    // open the BPF object file
    struct bpf_object *obj = bpf_object__open_file("xdp_pass.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // load it into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // get map file descriptors
    int ip_map_fd     = bpf_object__find_map_fd_by_name(obj, "ip_rules");
    int port_map_fd   = bpf_object__find_map_fd_by_name(obj, "port_rules");
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "config");
    int stats_map_fd  = bpf_object__find_map_fd_by_name(obj, "stats");

    // check maps are valid FIRST
    if (ip_map_fd < 0 || port_map_fd < 0 || config_map_fd < 0 || stats_map_fd < 0) {
        fprintf(stderr, "Failed to find one or more maps\n");
        return 1;
    }

    // find and attach the program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_pass_func");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP\n");
        return 1;
    }

    printf("XDP firewall attached to %s\n", ifname);

    // NOW load config (maps are confirmed valid, program is attached)
    if (load_config(config_file, ip_map_fd, port_map_fd, config_map_fd) < 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    // register signal handler for clean exit
    signal(SIGINT, handle_signal);

    printf("Firewall running. Press Ctrl+C to detach and exit.\n");

    // live stats loop
    while (running) {
        print_stats(stats_map_fd);
        sleep(1);
    }

    // clean detach
    printf("\nDetaching...\n");
    bpf_link__destroy(link);
    printf("Done.\n");
    
    return 0;
}