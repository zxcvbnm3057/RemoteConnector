#pragma once
#include <cstdint>
#pragma pack(push, 1)
struct ProxyHeader
{
    uint8_t type;         // 0=UDP, 1=TCP
    uint16_t target_port; // 目标端口，网络字节序
    uint16_t datalen;     // 数据长度，网络字节序
    // 后面紧跟data数据
};
#pragma pack(pop)
