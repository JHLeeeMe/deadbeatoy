/// include/snatcher.h
///

#ifndef SNATCHER_H
#define SNATCHER_H


#include "common.h"
#include "bpfocket.h"     // BPFapture
#include "ipcplusplus.h"  // MQueue

class SysvMQueueBuilder
{
public:  // rule of X
    SysvMQueueBuilder();
    ~SysvMQueueBuilder() = default;

    SysvMQueueBuilder(const SysvMQueueBuilder&) = delete;
    SysvMQueueBuilder& operator=(const SysvMQueueBuilder&) = delete;

    SysvMQueueBuilder(SysvMQueueBuilder&&) noexcept = default;
    SysvMQueueBuilder& operator=(SysvMQueueBuilder&&) noexcept = default;
public:
    static auto create_key(
        const std::string& dir_path, uint8_t proj_id) -> std::optional<key_t>;

    auto set_key(key_t key) -> SysvMQueueBuilder&;
    auto set_permission(sysv::mq::ePermission perm) -> SysvMQueueBuilder&;
    auto set_payload_max_size(size_t size) -> SysvMQueueBuilder&;

    [[nodiscard]]
    auto build() const -> sysv::mq::MQueue;

private:
    key_t key_;
    sysv::mq::ePermission perm_;
    size_t payload_max_size_;
};

auto create_MQueue(sysv::mq::ePermission perm, size_t buf_size)
        -> std::optional<sysv::mq::MQueue>;
auto create_BPFapture(bool promisc)
        -> std::pair<bpfapture::utils::eResultCode, bpfapture::core::BPFapture>;
auto print_eth_hdr(const struct ether_header& eth_hdr) -> void;
auto print_ip_hdr(const struct ip& ip_hdr) -> void;


#endif  // SNATCHER_H
