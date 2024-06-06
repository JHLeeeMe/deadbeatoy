/// src/snatcher.cpp
///

#include <optional>

#include "snatcher.h"

int quit = 0;

void signal_handler(int)
{
    quit = 1;
}

auto create_MQueue(sysv::mq::ePermission perm, const size_t buf_size)
        -> std::optional<sysv::mq::MQueue>;
auto create_BPFapture(const bool promisc)
        -> std::pair<bpfapture::utils::eResultCode, bpfapture::core::BPFapture>;
auto print_eth_hdr(const struct ether_header& eth_hdr) -> void;
auto print_ip_hdr(const struct ip& ip_hdr) -> void;

int main()
{
    ::signal(SIGINT, &signal_handler);

    namespace bpf_utils  = bpfapture::utils;
    namespace bpf_filter = bpfapture::filter;
    namespace bpf_core   = bpfapture::core;

    auto [code, sock] = create_BPFapture(true);
    if (code != bpf_utils::eResultCode::Success)
    {
        std::cerr << "[Error Code: " << static_cast<uint32_t>(code) << "]"
                  << "[errno: "      << sock.err() << "]"
                  << std::endl;
        return 2;
    }

    std::vector<uint8_t> buf(sock.mtu());

    auto mqueue_opt{ create_MQueue(sysv::mq::ePermission::RWRWRW, buf.size()) };
    if (!mqueue_opt.has_value())
    {
        return 1;
    }

    sysv::mq::MQueue mqueue{ std::move(mqueue_opt.value()) };
    const long mtype = 1;

    ssize_t received_bytes = 0;

    constexpr int kMaxCnt = 10;
    int max_cnt = kMaxCnt;
    while (!quit && max_cnt--)
    {
        received_bytes = sock.receive(buf.data(), buf.size());
        if (received_bytes < 0)
        {
            std::cerr << "[errno: " << sock.err() << "]" << std::endl;
            return 3;
        }

        std::cout << "received_bytes: " << received_bytes << '\n';

        std::string buf_str{ buf.begin(), buf.begin() + received_bytes };

        auto eth_hdr{ reinterpret_cast<struct ether_header*>(buf.data()) };
        print_eth_hdr(*eth_hdr);

        // Get upper layer protocol type (L3 Type)
        //uint16_t eth_type{ ntohs(eth_hdr->ether_type) };

        auto l3_pos{ buf.data() + sizeof(struct ether_header) };
        auto ip_hdr{ reinterpret_cast<struct ip*>(l3_pos) };
        print_ip_hdr(*ip_hdr);

        // Set payload of layer 3
        //const uint8_t* payload{ l3_pos + (ip_hdr->ip_hl * 4) };

        // Print TCP or UDP Header
        switch (ip_hdr->ip_p)
        {
        case IPPROTO_TCP:
            if (mqueue.send(buf_str, mtype) < 0)
            //if (mqueue.send_nowait(buf_str, mtype) < 0)
            {
                std::cerr << "[errno: " << mqueue.err() << "]" << std::endl;
            }

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

    for (size_t i = 0; i < kMaxCnt; i++)
    {
        if (mqueue.receive(mtype) < 0)
        {
            std::cerr << "[errno: " << mqueue.err() << "]" << std::endl;
        }

        std::cout << mqueue.msg() << '\n';
    }
    return 0;
}

auto create_BPFapture(const bool promisc)
        -> std::pair<bpfapture::utils::eResultCode, bpfapture::core::BPFapture>
{
    namespace bpf_utils  = bpfapture::utils;
    namespace bpf_filter = bpfapture::filter;
    namespace bpf_core   = bpfapture::core;

    bpf_core::BPFapture sock{ true };

    bpf_utils::eResultCode result_code{};
    result_code = sock.set_filter({ bpf_filter::eProtocolID::Ip });
    if (result_code != bpf_utils::eResultCode::Success)
    {
        if (sock.err() != 0)
        {
            std::cerr << "errno: " << sock.err() << std::endl;
        }
    }

    return { result_code, std::move(sock) };
}

auto print_eth_hdr(const struct ether_header& eth_hdr) -> void
{
    printf("Src: %02x", eth_hdr.ether_shost[0]);
    for (size_t i = 1; i < 6; i++)
    {
        printf(":%02x", eth_hdr.ether_shost[i]);
    }
    printf("\n");
    printf("Dst: %02x", eth_hdr.ether_dhost[0]);
    for (size_t i = 1; i < 6; i++)
    {
        printf(":%02x", eth_hdr.ether_dhost[i]);
    }
    printf("\n");
}

auto print_ip_hdr(const struct ip& ip_hdr) -> void
{
    printf("\tVersion    : %d\n", ip_hdr.ip_v);
    printf("\tHeader Len : %d (%d bytes)\n",
            ip_hdr.ip_hl, ip_hdr.ip_hl * 4);
    printf("\tIdent      : %d\n", ip_hdr.ip_id);
    printf("\tTTL        : %d\n", ip_hdr.ip_ttl);
    printf("\tL4 type    : %d\n", ip_hdr.ip_p);
    printf("\tSrc Address: %s\n", inet_ntoa(ip_hdr.ip_src));
    printf("\tDst Address: %s\n", inet_ntoa(ip_hdr.ip_dst));
}

auto create_MQueue(sysv::mq::ePermission perm, const size_t buf_size)
        -> std::optional<sysv::mq::MQueue>
{
    const key_t key{ sysv::utils::create_key("./", 1) };
    if (key < 0)
    {
        return std::nullopt;
    }

    try
    {
        return sysv::mq::MQueue(key, perm, buf_size);
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
        return std::nullopt;
    }
    catch (...)
    {
        return std::nullopt;
    }
}
