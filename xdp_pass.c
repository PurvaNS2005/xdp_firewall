#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>


#define STAT_TOTAL 0
#define STAT_PASSED 1
#define STAT_DROPPED 2
#define STAT_RATE_LIMITED 3
#define RATE_LIMIT_PACKETS 100  // max packets per IP before dropping


struct lpm_key {
    __u32 prefixlen;  // subnet prefix: 32 = exact IP, 24 = /24 subnet
    __u32 addr;       // IP address in network byte order
};


// blocked ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u32);
} port_rules SEC(".maps");

// blocked IPs
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_rules SEC(".maps");

// per-IP rate limiting counters
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // src IP
    __type(value, __u64);  // packet count
} rate_counters SEC(".maps");

// global stats counter
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// block/allow list mode flag
// 0 = blocklist mode (default allow, block matches)
// 1 = allowlist mode (default deny, allow matches)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");


// system uses x86 CPU which follows little endian format
// networks uses big endian format

// msg order : eth header -> ip header  -> transport layer header
// int pass(){
//     return XDP_PASS;
// }





SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;           // points to the start of data
    void *data_end = (void *)(long)ctx->data_end; // points to the end of packet data


    // count incoming packet
    __u32 key = STAT_TOTAL;
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if(value){
        (*value)++;
    }

    __u32 config_key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config, &config_key);
    __u32 is_allowlist = (mode && *mode == 1) ? 1 : 0;      // mode = 0 => blocklist mode, else allowlist mode




    // physical layer
    struct ethhdr *eth = data;
    if((void *)(eth+1) > data_end){
     //   bpf_printk("Blocked at first filter......");
        return XDP_PASS;
    }

    // checks protocol: IPv4, IPv6, ARP, etc
    if(eth->h_proto != bpf_htons(ETH_P_IP)){        // htons->host to network short: changes little endian(followed by my system) to big endian(used in network protocols)
     //   bpf_printk("Blocked at second filter......");
        return XDP_PASS;
    }

    // ip layer
    // currently extracted data for ip fields are not converted to little endian format

    struct iphdr *ip = (void *)(eth + 1);
    if((void *)(ip + 1) > data_end){
      //  bpf_printk("Blocked at third filter......");
        return XDP_PASS;
    }

    if(ip->ihl < 5)return XDP_PASS;

    __u32 src_ip = ip->saddr, dst_ip = ip->daddr;
    __u8 protoc = ip->protocol;

     struct lpm_key curr_key = {};
    curr_key.addr = src_ip;
    curr_key.prefixlen = 32;
    __u32 ip_match = 0;
    if(bpf_map_lookup_elem(&ip_rules, &curr_key))
        ip_match = 1;






    if(protoc != IPPROTO_TCP){
       // bpf_printk("Blocked at fourth filter......");
        return XDP_PASS;         // passing non - tcp data for now (subject to change)***
    }
    
    // transport layer
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if((void *)(tcp+1) > data_end){
        //bpf_printk("Blocked at fifth filter......");
        return XDP_PASS;
    }
    __u16 src_port = bpf_ntohs(tcp->source), dst_port = bpf_ntohs(tcp->dest);
    // if (src_port == 443) {
    //     bpf_printk("Blocked at sixth filter......");
    //     return XDP_DROP;
    // }


    // struct lpm_key curr_key = {};
    // curr_key.addr = src_ip;
    // curr_key.prefixlen = 32;

    
    // __u32 ip_match = 0;
    // {
    //     void *r = bpf_map_lookup_elem(&ip_rules, &curr_key);
    //     ip_match = r ? 1 : 0;
    // }  // r is gone here — compiler MUST write ip_match to stack
    __u32 port_match = 0;
    {
        void *p = bpf_map_lookup_elem(&port_rules, &dst_port);
        if(p) port_match = 1;
    }
    if(!port_match){
        void *q = bpf_map_lookup_elem(&port_rules, &src_port);
        if(q) port_match = 1;
    }
    
    __u32 is_rate_limited = 0;
    __u64 *counter = bpf_map_lookup_elem(&rate_counters, &src_ip);
    if(counter){
        (*counter)++;
        if(*counter > RATE_LIMIT_PACKETS){
            is_rate_limited = 1;
        }
    }else{
        __u64 tmp = 1;
        bpf_map_update_elem(&rate_counters, &src_ip, &tmp, BPF_ANY);
    }

    // determine drop decision based on mode
   // blocklist mode: each match is an independent drop decision
    // allowlist mode: each match is an independent pass decision
    if(ip_match){
        if(!is_allowlist){
            __u32 dk = STAT_DROPPED;
            __u64 *dv = bpf_map_lookup_elem(&stats, &dk);
            if(dv) (*dv)++;
            return XDP_DROP;
        }
        // allowlist mode — IP is permitted, skip to pass
        goto do_pass;
    }

    if(port_match){
        if(!is_allowlist){
            __u32 dk = STAT_DROPPED;
            __u64 *dv = bpf_map_lookup_elem(&stats, &dk);
            if(dv) (*dv)++;
            return XDP_DROP;
        }
        // allowlist mode — port is permitted, skip to pass
        goto do_pass;
    }

    if(is_rate_limited){
        __u32 dk = STAT_RATE_LIMITED;
        __u64 *dv = bpf_map_lookup_elem(&stats, &dk);
        if(dv) (*dv)++;
        return XDP_DROP;
    }

    // allowlist mode — nothing matched → drop
    if(is_allowlist){
        __u32 dk = STAT_DROPPED;
        __u64 *dv = bpf_map_lookup_elem(&stats, &dk);
        if(dv) (*dv)++;
        return XDP_DROP;
    }

    do_pass:;
    __u32 pass_key = STAT_PASSED;
    __u64 *pass_val = bpf_map_lookup_elem(&stats, &pass_key);
    if(pass_val) (*pass_val)++;

    bpf_printk("src=%u dst=%u sport=%u dport=%u\n",
                src_ip, dst_ip, src_port, dst_port);
    return XDP_PASS;
    
    
    bpf_printk("src=%u dst=%u sport=%u dport=%u\n", src_ip, dst_ip, src_port, dst_port);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";


// 1. Setup veth pair
// bashsudo ip link add veth0 type veth peer name veth1
// sudo ip addr add 10.0.0.1/24 dev veth0
// sudo ip link set veth0 up


// 2. Setup testns
// bashsudo ip netns add testns
// sudo ip link set veth1 netns testns
// sudo ip netns exec testns ip addr add 10.0.0.2/24 dev veth1
// sudo ip netns exec testns ip link set veth1 up

// # 1. Compile
// clang -O2 -g -target bpf -c xdp_pass.c -o xdp_pass.o

// # 2. Detach
// sudo ip link set dev enp7s0 xdp off

// # 3. Attach
// sudo ip link set dev enp7s0 xdp obj xdp_pass.o sec xdp

// # 4. Verify
// sudo bpftool prog show | grep xdp
// ip link show enp7s0

// # 5. check bpf logs
// sudo cat /sys/kernel/debug/tracing/trace_pipe





// ┌─────────────────────────────────────────────────────────┐
// │                    HOST NAMESPACE                        │
// │                                                          │
// │   $ curl http://10.0.0.2:8080                           │
// │          │                                               │
// │          ▼                                               │
// │   ┌─────────────┐                                        │
// │   │   veth0     │  ◄── XDP firewall lives here          │
// │   │  10.0.0.1   │      checks every incoming packet     │
// │   └─────────────┘                                        │
// │          │  ▲                                            │
// │  request │  │ reply                                      │
// │          │  │                                            │
// └──────────│──│────────────────────────────────────────────┘
//            │  │        (virtual cable)
// ┌──────────│──│────────────────────────────────────────────┐
// │          ▼  │            TESTNS NAMESPACE                 │
// │   ┌─────────────┐                                        │
// │   │   veth1     │                                        │
// │   │  10.0.0.2   │                                        │
// │   └─────────────┘                                        │
// │          │                                               │
// │          ▼                                               │
// │   python3 -m http.server 8080                           │
// │                                                          │
// └─────────────────────────────────────────────────────────┘