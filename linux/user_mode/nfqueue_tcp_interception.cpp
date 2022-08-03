#include <memory>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
  
extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}
  
#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)
  
#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)
  
using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)
  
static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    THROW_IF_TRUE(ph == nullptr, "Failed to get packet header");
  
    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can't get payload data");
  
    // TCP header size should be aligned in the 32-bit words
    // Need to extend packet by new options size and padding bytes
    // In our case it is 1 byte
    const int extraOptionSize = 3;
    pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len + extraOptionSize + 1, 0);
    THROW_IF_TRUE(pkBuff == nullptr, "Failed to allocate new pft_buff");
    SCOPED_GUARD( pktb_free(pkBuff); );

    iphdr *ip = nfq_ip_get_hdr(pkBuff);
    THROW_IF_TRUE(ip == nullptr, "Failed to get IP header");

    // Need to update the total length of the IP header with size of new TCP option with padding
    // and update IP header checksum
    ip->tot_len = htons(ntohs(ip->tot_len) + extraOptionSize + 1);
    nfq_ip_set_checksum(ip);

    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can't set transport header.");

    if (ip->protocol != IPPROTO_TCP)
    {
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
    }

    tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
    THROW_IF_TRUE(tcp == nullptr, "Failed to get TCP header.");

    if (!tcp->syn)
    {
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
    }

    // TCP offset is specified in 32-bit words so need to multiply its value by 4 
    char* extraOptions = reinterpret_cast<char*>(tcp) + tcp->doff * 4;
    // TCP options from 79-252 reserved so we can use value from this range
    extraOptions[0] = 100;
    // Size in bytes of TCP option including Kind and Size fields
    extraOptions[1] = 3;
    // Set option value 2 for Linux
    extraOptions[2] = 2;
    // Need to set padding byte to 0
    extraOptions[3] = 0;

    // Need to update data offset for TCP header
    tcp->doff += 1;

    // Need to update TCP header checksum
    nfq_tcp_compute_checksum_ipv4(tcp, ip);

    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
}

int main()
{
    try
    {
        nfq_handle* handler = nfq_open();
        THROW_IF_TRUE(handler == nullptr, "Can't open hfqueue handler.");
        SCOPED_GUARD(nfq_close(handler); );

        nfq_q_handle* queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
        THROW_IF_TRUE(queue == nullptr, "Can't create queue handler.");
        SCOPED_GUARD(nfq_destroy_queue(queue); );

        THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can\'t set queue copy mode.");

        std::cout << "Start processing Netlink socket data" << std::endl;

        int fd = nfq_fd(handler);
        std::array<char, 0x10000> buffer;
        for (;;)
        {
            int len = read(fd, buffer.data(), buffer.size());
            THROW_IF_TRUE(len < 0, "Issue while read");
            nfq_handle_packet(handler, buffer.data(), len);
        }

        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what();
    }

    return -1;
 }
