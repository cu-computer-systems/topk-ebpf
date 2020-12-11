#define KBUILD_MODNAME "topk"
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "xdp_helper.h" 

struct ipcount {
    uint32_t ip;
    uint64_t count;
};

struct summary {
    struct ipcount sumipcnt[3];
};

BPF_PERCPU_ARRAY(rxcnt, long, 1); //Keeps track of (eth) packets recvd

BPF_HASH(localhash, uint32_t, uint64_t, 1<<10); //Local hash to count IPs
BPF_HASH(globalhash, uint32_t, uint64_t, 1<<10); //Global hash to get TopK 

BPF_ARRAY(iparray, uint32_t, 1<<10); // localIP array to sort local hash elements
BPF_ARRAY(iparraylen, long, 1); // localIP array length
BPF_ARRAY(ipcntarray, struct ipcount, 1<<10); // Array of struct ipcount to sort 
BPF_ARRAY(topkarray, struct ipcount, 3); // Array of struct ipcount to str topk 
BPF_ARRAY(globaliparray, uint32_t, 1<<10); // IP array to track global IPs 
BPF_ARRAY(globaliparraylen, long, 1); // globalIP array length
BPF_ARRAY(delta, long, 1); // global delta value
BPF_ARRAY(sumlen, long, 1); // global summary queue summq len 

BPF_QUEUE(bit0, struct ipcount, 1<<10);
BPF_QUEUE(bit1, struct ipcount, 1<<10);
BPF_QUEUE(summq, struct summary, 1<<10);

int topk(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    long *pvalue, *val, *tval, *gval;
    uint64_t nxth_off = sizeof(*eth);
    uint8_t ipver;
    uint16_t h_proto;
    uint32_t iptemp, ipproto, ipsrc; uint64_t zero = 0;
    struct ipcount qvalue; 
    struct summary svalue, mvalue; 
    __builtin_memset(&mvalue, 0, sizeof(mvalue));
    __builtin_memset(&svalue, 0, sizeof(svalue));
    __builtin_memset(&qvalue, 0, sizeof(qvalue));
    int issummqfull = 0, localdelta = 0;

    //Check whether we have at least one valid ethhdr 
    if (data + nxth_off  > data_end)
        return XDP_DROP;

    //Get protocol inside eth packet
    h_proto = eth->h_proto;
    //bpf_trace_printk("Received eth packet \n");

    //Don't care about ARP packets
    if (h_proto == htons(ETH_P_ARP))
        return XDP_PASS;

    //Yay found IP packet
    else if(h_proto == htons(ETH_P_IP)){
        bpf_trace_printk("-------------\n");
        //bpf_trace_printk("Received IP packet \n");
        struct iphdr *iph = data + nxth_off;

        //We expect a UDP/TCP packet?
	if ((void*) &iph[1] > data_end)
	    return XDP_ABORTED;

        ipproto = parse_ipv4(data, nxth_off, data_end);
        //bpf_trace_printk("IP protocol is %d\n", ipproto);
        
        ipver = iph->version;
        //bpf_trace_printk("IP version: %d\n", ipver);

        /* 
         * This where the fun starts
         */

        if(ipver == 4){
            ipsrc = ntohl(iph->saddr);
            //bpf_trace_printk("IP source address: %x\n", ipsrc);

            //Count the packet
            pvalue = rxcnt.lookup(&zero);
            if (pvalue)
                *pvalue += 1;
                
            val = localhash.lookup_or_try_init(&ipsrc, &zero);
            if(val){
                //Saving new IP address in localhash and the iparray
                if(*val == 0){
                    bpf_trace_printk("New IP found!");
                    tval = iparraylen.lookup(&zero);
                    if(tval){ //Adding new IP to iparray
                        iparray.update(tval, &ipsrc);
                        bpf_trace_printk(
                                "Added %x to IPList[%d]\n", 
                                ipsrc, 
                                *tval);
                        *tval += 1;
                    }
                }
                //Incrementing packet count for IPSRC in localhash
                *val += 1;
            }

        }


        //Sorting iparray to get topk in localhash
        val = rxcnt.lookup(&zero);
        if (val && *val >= 64){
            rxcnt.update(&zero, &zero);
            //bpf_trace_printk("8 unique IPs recvd\n");
            
            int i, j, index, h, mask;
            int bit = 0, bit0len = 0, bit1len = 0; 
            int bitlen = sizeof(int)*8;
            
            // Generating ipcntarray 
            for(i = 0; i < 8; i++){
                index = i;
                //Get IP
                val = iparray.lookup(&index);
                if(val){
                    iptemp = *((uint32_t*)val);
                    qvalue.ip = iptemp;
                }
                //Get count for above IP
                tval = localhash.lookup(&(qvalue.ip));
                if(tval){
                    qvalue.count = *((uint64_t*)tval);
                }

                //Add struct IP count to ipcntarray
                ipcntarray.update(&index, &qvalue);
                //Clear local counters for next window
                localhash.delete(&(qvalue.ip));
                __builtin_memset(&qvalue, 0, sizeof(qvalue));

            }

            for(i = 0, mask = 1; i < 32; ++i, mask <<= 1){
                //Sorting begins
                //bpf_trace_printk("Sorting...\n");
                bit1len = 0;
                bit0len = 0;

                for(j = 0; j < 8; ++j){
                    index = j;
                    //bpf_trace_printk("Nesting...ipcntarray[]\n");

                    //Get jth element from ipcntarray
                    val = ipcntarray.lookup(&index);
                    if(val) {
                        qvalue = *((struct ipcount*)val); 
                        //Apply mask and Enqueue in bit0 or bit1
                        if(qvalue.count & mask){
                            bit1.push(&qvalue, BPF_ANY);
                            bit1len++;
                        }
                        else {
                            bit0.push(&qvalue, BPF_ANY);
                            ++bit0len;
                        }
                    }
                    
                }

                for(j = 0; j < 8-bit1len; ++j){
                    //bpf_trace_printk("Bit0 insert..\n");
                    //Dequeue and insert back into ipcntarray
                    index = j;
                    bit0.pop(&qvalue);
                    ipcntarray.update(&index, &qvalue);
                }

                for (; j < 8; ++j){
                    //bpf_trace_printk("Bit1 insert..\n");
                    //Dequeue and insert back into iparray
                    index = j;
                    bit1.pop(&qvalue);
                    ipcntarray.update(&index, &qvalue);
                }
            }//ipcntarray sorted

            //Carry on with TopK algorithm
            for(i = 0; i < 3; i++){
                index = 7 - i;
                //Get the topk from ipcntarray
                val = ipcntarray.lookup(&index);
                if(val) {
                    //Add topk of localhash to globalhash
                    qvalue = *((struct ipcount*)val); 
                    iptemp = qvalue.ip;
                    if(!iptemp)
                        continue;
                    tval = globalhash.lookup_or_try_init(
                            &(iptemp), 
                            &zero);

                    //Add new IPs to globaliparray to keep track of
                    //globalhash unique entries
                    if(tval){
                        if(*tval == 0){
                            gval = globaliparraylen.lookup(&zero);
                            if(gval){
                                globaliparray.update(gval, &(iptemp));
                                *gval += 1;
                            }
                        }
                        *tval += qvalue.count;
                    }

                    //Create summary mvalue
                    mvalue.sumipcnt[i].ip = qvalue.ip;
                    mvalue.sumipcnt[i].count = qvalue.count;
                }
            }

            uint32_t zero32 = 0;
            //Printing sorted ipcntarray
            for(i = 0; i < 8; i++){
                index = i;
                val = ipcntarray.lookup(&index);
                if(val){
                    qvalue = *((struct ipcount*)(val)); 
                    bpf_trace_printk("%x:%d\n", qvalue.ip, qvalue.count);
                }
                ipcntarray.update(&index, &zero32);
                iparraylen.update(&zero, &zero);
            }

            //If summq full pop
            val = sumlen.lookup(&zero);
            if(val){
                if(*val == 4)
                    issummqfull = 1;
            }
            if(issummqfull){
                summq.pop(&svalue);
                //Subtract summary S' ip counts from globalhash
                val = globalhash.lookup(&(svalue.sumipcnt[0].ip));
                if(val){
                    *val = *val - svalue.sumipcnt[0].count;
                    if(*val == 0)
                        globalhash.delete(&(svalue.sumipcnt[1].ip));
                }
                val = globalhash.lookup(&(svalue.sumipcnt[1].ip));
                if(val){
                    *val = *val - svalue.sumipcnt[1].count;
                    if(*val == 0)
                        globalhash.delete(&(svalue.sumipcnt[1].ip));
                }
                val = globalhash.lookup(&(svalue.sumipcnt[2].ip));
                if(val){
                    *val = *val - svalue.sumipcnt[2].count;
                    if(*val == 0)
                        globalhash.delete(&(svalue.sumipcnt[1].ip));
                }
                //Modify delta
                val = delta.lookup(&zero);
                if(val){
                    *val -= svalue.sumipcnt[2].count;
                    localdelta = *val;
                }
                //Update summq len 
                val = sumlen.lookup(&zero);
                if(val){
                    *val -= 1;
                }

                //Print Topk
                bpf_trace_printk("Topk:\n");
                for(i = 0; i < 1<<10; i++){
                    index = i;
                    val = globaliparray.lookup(&index);
                    if(val){
                        tval = globalhash.lookup(val);
                        if(tval){
                            if(*tval > localdelta){
                                bpf_trace_printk("%x:%d\n", 
                                        *(uint32_t*)val, 
                                        *(uint64_t*)tval);
                            }
                        }
                    }
                }
            }

            //Modify delta
            val = delta.lookup(&zero);
            if(val){
                *val += mvalue.sumipcnt[2].count; 
                bpf_trace_printk("Delta:%d\n", *val);
            }

            //Push summary mvalue to summq
            summq.push(&(mvalue), BPF_EXIST);

            //Update summq len 
            val = sumlen.lookup(&zero);
            if(val){
                *val += 1;
            }

        }

	if(ipproto == 254){ // a custom ip protol packet is found
		swap_eth(data);
		swap_ip(iph);
	}

        return XDP_PASS;

    }

    //Default case: unknown packet  
    else
        return XDP_PASS; 
    
    return XDP_DROP;

}

