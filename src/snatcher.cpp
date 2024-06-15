/// src/snatcher.cpp
///

#include "snatcher.h"

SysvMQueueBuilder::SysvMQueueBuilder()
    : key_{ 255 }
    , perm_{ sysv::mq::ePermission::RWR_R_ }
    , payload_max_size_{ 128 }
{
}

auto SysvMQueueBuilder::create_key(
    const std::string& dir_path, const uint8_t proj_id) -> std::optional<key_t>
{
    const int key = sysv::utils::create_key(dir_path, proj_id);
    if (key == -1)
    {
        return std::nullopt;
    }

    return key;
}

auto SysvMQueueBuilder::set_key(const key_t key) -> SysvMQueueBuilder&
{
    key_ = key;
    return *this;
}

auto SysvMQueueBuilder::set_permission(const sysv::mq::ePermission perm)
        -> SysvMQueueBuilder&
{
    perm_ = perm;
    return *this;
}

auto SysvMQueueBuilder::set_payload_max_size(const size_t size)
        -> SysvMQueueBuilder&
{
    payload_max_size_ = size;
    return *this;
}

auto SysvMQueueBuilder::build() const -> sysv::mq::MQueue
{
    return sysv::mq::MQueue(key_, perm_, payload_max_size_);
}

auto create_MQueue(const sysv::mq::ePermission perm, const size_t buf_size)
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

auto create_BPFapture(const bool promisc)
        -> std::pair<bpfapture::utils::eResultCode, bpfapture::core::BPFapture>
{
    namespace bpf_utils  = bpfapture::utils;
    namespace bpf_filter = bpfapture::filter;
    namespace bpf_core   = bpfapture::core;

    bpf_core::BPFapture sock{ true };

    bpf_utils::eResultCode result_code{
        sock.set_filter({ bpf_filter::eProtocolID::Ip }) };
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
