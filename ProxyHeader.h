#pragma once
#include <cstdint>
#pragma pack(push, 1)

struct ProxyHeader
{
    uint8_t type;         // 0=UDP, 1=TCP, 2=UDP_HOLE_PUNCHING
    uint16_t target_port; // 目标端口，网络字节序
    uint16_t datalen;     // 数据长度，网络字节序
    uint16_t client_port; // 客户端端口，网络字节序 (仅用于UDP hole punching)
    // 其后跟data内容
};

// UDP hole punching packet types
enum class UdpHolePunchPacketType : uint8_t
{
    HANDSHAKE = 0,    // 握手包
    ACK = 1,          // 确认包
    HEARTBEAT = 2     // 心跳包
};

struct UdpHolePunchPacket
{
    UdpHolePunchPacketType type;
    uint32_t timestamp;   // 时间戳，网络字节序
    uint16_t data_len;    // 数据长度，网络字节序
    // 其后跟data内容
};

#pragma pack(pop)
