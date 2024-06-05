/// src/snatcher.cpp
///

#include "snatcher.h"

int quit = 0;

void signal_handler(int)
{
    quit = 1;
}

int main()
{
    ::signal(SIGINT, &signal_handler);

    namespace utils  = bpfapture::utils;
    namespace filter = bpfapture::filter;
    namespace core   = bpfapture::core;

    core::BPFapture sock{ true };

    utils::eResultCode result_code{};
    result_code = sock.set_filter({ filter::eProtocolID::Ip });
    if (result_code != utils::eResultCode::Success)
    {
        std::cerr <<
            "result code: " << static_cast<uint32_t>(result_code) << std::endl;
        if (sock.err() != 0)
        {
            std::cerr << "errno: " << sock.err() << std::endl;
        }

        return 1;
    }

    std::vector<uint8_t> buf(sock.mtu());
    ssize_t received_bytes = 0;

    int max_cnt = 10;
    while (!quit && max_cnt--)
    {
        received_bytes = sock.receive(buf.data(), buf.size());
        if (received_bytes < 0)
        {
            std::cerr << "errno: " << sock.err() << std::endl;
            return 2;
        }

        std::cout << "received_bytes: " << received_bytes << '\n';

        auto eth_hdr{ reinterpret_cast<struct ether_header*>(buf.data()) };

        printf("Src: %02x", eth_hdr->ether_shost[0]);
        for (size_t i = 1; i < 6; i++)
        {
            printf(":%02x", eth_hdr->ether_shost[i]);
        }
        printf("\n");
        printf("Dst: %02x", eth_hdr->ether_dhost[0]);
        for (size_t i = 1; i < 6; i++)
        {
            printf(":%02x", eth_hdr->ether_dhost[i]);
        }
        printf("\n");

        // Get upper layer protocol type (L3 Type)
        uint16_t eth_type{ ntohs(eth_hdr->ether_type) };

        auto l3_pos{ buf.data() + sizeof(struct ether_header) };
        auto ip_hdr{ reinterpret_cast<struct ip*>(l3_pos) };

        printf("\tVersion    : %d\n", ip_hdr->ip_v);
        printf("\tHeader Len : %d (%d bytes)\n",
               ip_hdr->ip_hl, ip_hdr->ip_hl * 4);
        printf("\tIdent      : %d\n", ip_hdr->ip_id);
        printf("\tTTL        : %d\n", ip_hdr->ip_ttl);
        printf("\tL4 type    : %d\n", ip_hdr->ip_p);
        printf("\tSrc Address: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("\tDst Address: %s\n", inet_ntoa(ip_hdr->ip_dst));

        const uint8_t* payload{ l3_pos + (ip_hdr->ip_hl * 4) };

        // Print TCP or UDP Header
        switch (ip_hdr->ip_p)
        {
        case IPPROTO_TCP:
            /*
            tcp_hdr = reinterpret_cast<struct tcphdr*>(payload);
            print_tcp_hdr(tcp_hdr);
            break;
            */
        case IPPROTO_UDP:
            /*
            udp_hdr = reinterpret_cast<struct udphdr*>(payload);
            print_udp_hdr(udp_hdr);
            break;
            */
        default:
            break;
        }
    }

    return 0;
}
