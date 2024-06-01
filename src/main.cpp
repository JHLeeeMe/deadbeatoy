//
// Created by JHLeeeMe on 2024-06-01.
//

#include <iostream>

#include "bpfocket.h"
#include "ipcplusplus.h"

int main()
{
    std::cout << "Hello, world!" << std::endl;

    bpfapture::core::BPFapture cap{ true };
    if (cap.err() != 0)
    {
        std::cerr << cap.err() << std::endl;
        return 1;
    }

    std::cout << "system mtu: " << cap.mtu() << std::endl;

    return 0;
}
