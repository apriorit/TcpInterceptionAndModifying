/*****************************************************
 * This code was compiled and tested on Ubuntu 18.04.1
 * with kernel version 4.15.0
 *****************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>

 static uint16_t checksum(uint32_t sum, uint16_t *buf, int size)
 {
         while (size > 1) {
                 sum += *buf++;
                 size -= sizeof(uint16_t);
         }
         if (size) {
                 sum += (uint16_t)*(uint8_t *)buf;
         }
 
         sum = (sum >> 16) + (sum & 0xffff);
         sum += (sum >>16);
 
         return (uint16_t)(~sum);
 }
 
 static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph)
 {
         uint32_t sum = 0;
         uint32_t len = tcph->doff * 4;
         uint8_t *payload = (uint8_t *)tcph;
 
         sum += (iph->saddr >> 16) & 0xFFFF;
         sum += (iph->saddr) & 0xFFFF;
         sum += (iph->daddr >> 16) & 0xFFFF;
         sum += (iph->daddr) & 0xFFFF;
         sum += htons(IPPROTO_TCP);
         sum += htons(len);
 
         return checksum(sum, (uint16_t *)payload, len);
 }

static struct nf_hook_ops *nfho = NULL;

static unsigned int callback(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sk_buff *new_skb;
    char* extra_options;
    const int extra_option_size = 4;
    const int multiplicity = 4;
    const int option_kind = 100;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    if (!tcph || !tcph->syn)
        return NF_ACCEPT;

    if (ntohs(tcph->dest) != 6044)
        return NF_ACCEPT;
        
    printk(KERN_ALERT "\n Got SYN packet for Dest port %d\n", ntohs(tcph->dest));
        
    extra_options = (char*)tcph + tcph->doff * multiplicity - extra_option_size;
    if (extra_options[0] == option_kind) {
        printk(KERN_ALERT "\n Skip already processed packet that has option\n");
        return NF_ACCEPT;
    }

    new_skb = skb_copy_expand(skb, skb_headroom(skb), skb->tail + extra_option_size, GFP_ATOMIC);
    if (!new_skb)
        return NF_ACCEPT;
    
    iph = ip_hdr(new_skb);
    if (!iph) {
        kfree_skb(new_skb);
        return NF_ACCEPT;
    }

    iph->tot_len = htons(ntohs(iph->tot_len) + extra_option_size);
    iph->check = 0;
    iph->check = checksum(0, (uint16_t *)iph, iph->ihl * multiplicity);
    
    tcph = tcp_hdr(new_skb);
    if (!tcph) {
        kfree_skb(new_skb);
        return NF_ACCEPT;
    }
        
    // TCP offset is specified in 32-bit words so need to multiply its value by 4 
    extra_options = (char*)tcph + tcph->doff * multiplicity;
    // TCP options from 79-252 reserved so we can use value from this range
    extra_options[0] = option_kind;
    // Size in bytes of TCP option including Kind and Size fields
    extra_options[1] = 3;
    // Set option value 2 for Linux
    extra_options[2] = 2;
    // Need to set padding byte to 0
    extra_options[3] = 0;

    // Need to update data offset for TCP header
    tcph->doff += 1;

    // Need to update TCP header checksum
    tcph->check = 0;
    tcph->check = tcp_checksum(iph, tcph);
       
    skb_put(new_skb, multiplicity);

    if (ip_local_out(state->net, state->sk, new_skb)) {
        kfree_skb(new_skb);
        return NF_ACCEPT;
    }
        
    printk(KERN_ALERT "\n Added TCP option for SYN packet for Dest port %d\n", ntohs(tcph->dest));

    return NF_DROP;
}

static int __init tcp_parser_init(void)
{
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    
    /* Initialize netfilter hook */
    nfho->hook 	= (nf_hookfn*)callback;		/* hook function */
    nfho->hooknum 	= NF_INET_LOCAL_OUT;		/* sent packets */
    nfho->pf 	= PF_INET;					/* IPv4 */
    nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
    
    return nf_register_net_hook(&init_net, nfho);
}

static void __exit tcp_parser_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
}

MODULE_LICENSE("GPL");

module_init(tcp_parser_init);
module_exit(tcp_parser_exit);
