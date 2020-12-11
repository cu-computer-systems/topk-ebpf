#ifndef __XDP_HELPER_H
#define __XDP_HELPER_H

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define __bswap64(x) \
    ((uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
                (((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
                (((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
                (((uint64_t)(x) & 0x000000ff00000000ULL) >>  8) | \
                (((uint64_t)(x) & 0x00000000ff000000ULL) <<  8) | \
                (((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
                (((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
                (((uint64_t)(x) & 0x00000000000000ffULL) << 56)))
#define ntohll(x) __bswap64(x)
#define htonll(x) __bswap64(x)


static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;
    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }
    if (bufsz == 1)
        sum += *(unsigned char *)buf;
    
	sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;
    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline void update_eth(void *data, unsigned short mac_dst[])
{
    unsigned short *p = data;
    unsigned short dst[3];

    p[3] = p[0];
    p[4] = p[1];
    p[5] = p[2];
    p[0] = mac_dst[0];
    p[1] = mac_dst[1];
    p[2] = mac_dst[2];

}

static inline void update_ip(struct iphdr *iph, u32 ip_dst){
    //u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = ip_dst;
    iph->check = 0;
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
}

static inline void swap_eth(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];

}

static inline void swap_ip(struct iphdr *iph){
    u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;
}

//HeapSort implementation for b elements/packets
#define b 1<<3

typedef struct element {
    u32 ip;
    u64 count;
} element;

int compare_element(element *e1, element *e2){
    if (e1 && e2){
        if(e1->count > e2->count)
            return 1;
        else if (e1->count < e2->count)
            return -1;
        else
            return 0;
    }
    return 2;
}

#endif
