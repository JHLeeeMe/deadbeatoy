/// test/snatcher_test.cpp
///

#include "gtest/gtest.h"

#include "snatcher.h"

namespace utils  = bpfapture::utils;
namespace filter = bpfapture::filter;
namespace core   = bpfapture::core;

TEST(main, BPFapture)
{
    core::BPFapture sock{ true };
    utils::eResultCode result_code{
        sock.set_filter({ filter::eProtocolID::Ip }) };
    if (result_code != utils::eResultCode::Success)
    {
        std::cerr <<
            "result code: " << static_cast<uint32_t>(result_code) << std::endl;
        if (sock.err() != 0)
        {
            std::cerr << "errno: " << sock.err() << std::endl;
        }

        return;
    }

    {  // filter
        struct sock_filter* filter{ sock.filter().filter };

        auto filter_vec{ filter::gen_bpf_code({ filter::eProtocolID::Ip }) };
        for (size_t i = 0; i < filter_vec.size(); i++)
        {
            ASSERT_EQ(filter_vec[i].code, filter[i].code);
            ASSERT_EQ(filter_vec[i].jt, filter[i].jt);
            ASSERT_EQ(filter_vec[i].jf, filter[i].jf);
            ASSERT_EQ(filter_vec[i].k, filter[i].k);
        }

        ASSERT_EQ(filter_vec.size(), sock.filter().len);
    }

    {  // mtu 
        int sockfd = sock.fd();

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, sock.ifname().c_str(), sock.ifname().length());
        if (::ioctl(sockfd, SIOCGIFMTU, &ifr) < 0)
        {
            std::cerr << "ioctl" << std::endl;
            return;
        }

        ASSERT_EQ(ifr.ifr_mtu, sock.mtu());
    }

    {  // receive
        std::vector<uint8_t> buf(sock.mtu());

        uint32_t cnt = 5;
        sock.set_filter({ filter::eProtocolID::Tcp });

        while (cnt--)
        {
            ssize_t received_bytes = sock.receive(buf.data(), buf.size());
            if (received_bytes < 0)
            {
                std::cerr << "errno: " << sock.err() << std::endl;
                return;
            }

            auto l3_pos{ buf.data() + sizeof(struct ether_header) };
            auto ip_hdr{ reinterpret_cast<struct ip*>(l3_pos) };

            ASSERT_EQ(
                static_cast<uint8_t>(filter::eProtocolID::Tcp),
                ip_hdr->ip_p
            );
        }
    }
}
