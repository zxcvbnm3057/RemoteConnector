#pragma once
#include <cstdint>
#pragma pack(push, 1)
struct ProxyHeader
{
    uint8_t type;         // 0=UDP, 1=TCP
    uint16_t target_port; // Ŀ��˿ڣ������ֽ���
    uint16_t datalen;     // ���ݳ��ȣ������ֽ���
    // �������data����
};
#pragma pack(pop)
