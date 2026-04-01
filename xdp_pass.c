#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>


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
    __u32 src_ip = ip->saddr, dst_ip = ip->daddr;
    __u8 protoc = ip->protocol;
    if(protoc != IPPROTO_TCP){
       // bpf_printk("Blocked at fourth filter......");
        return XDP_PASS;         // passing non - tcp data for now (subject to change)***
    }
    if(ip->ihl < 5)return XDP_PASS;
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

    bpf_printk("src=%u dst=%u sport=%u dport=%u\n", src_ip, dst_ip, src_port, dst_port);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";


// # 1. Compile
// clang -O2 -target bpf -c xdp_pass.c -o xdp_pass.o

// # 2. Detach
// sudo ip link set dev wlp8s0 xdp off

// # 3. Attach
// sudo ip link set dev wlp8s0 xdp obj xdp_pass.o sec xdp

// # 4. Verify
// sudo bpftool prog show | grep xdp
// ip link show wpl8s0

// # 5. check bpf logs
// sudo cat /sys/kernel/debug/tracing/trace_pipe