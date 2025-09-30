/**
 * Copyright 2025 Fengying <zxcvbnm3057@outlook.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "ProxyHeader.h"

#pragma comment(lib, "Ws2_32.lib")

namespace
{
    constexpr size_t kMaxPayloadSize = 65535;

    enum class LogLevel
    {
        Info,
        Warn,
        Error,
        Debug
    };

    enum class ProxyProtocol : uint8_t
    {
        UDP = 0,
        TCP = 1
    };

    struct ConnectionContext
    {
        SOCKET socket = INVALID_SOCKET;
        ProxyProtocol protocol = ProxyProtocol::UDP;
        uint16_t targetPort = 0;
        std::string remoteTag;
        std::atomic_bool running{true};
    };

    std::atomic_uint64_t g_connectionId{0};
    std::mutex g_logMutex;

    std::string timestamp()
    {
        using namespace std::chrono;
        const auto now = system_clock::now();
        const auto t = system_clock::to_time_t(now);
        std::tm tmBuf{};
        ::localtime_s(&tmBuf, &t);

        std::ostringstream oss;
        oss << std::put_time(&tmBuf, "%Y-%m-%d %H:%M:%S");

        const auto millis = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
        oss << '.' << std::setfill('0') << std::setw(3) << millis.count();
        return oss.str();
    }

    const char *levelToString(LogLevel level)
    {
        switch (level)
        {
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warn:
            return "WARN";
        case LogLevel::Error:
            return "ERROR";
        case LogLevel::Debug:
            return "DEBUG";
        default:
            return "INFO";
        }
    }

    void logMessage(LogLevel level, const std::string &tag, const std::string &message)
    {
        std::lock_guard<std::mutex> guard(g_logMutex);
        std::cout << '[' << timestamp() << "]" << '[' << levelToString(level) << "]" << tag << ' ' << message
                  << std::endl;
    }

    std::string formatRemote(const sockaddr_storage &addr)
    {
        char host[NI_MAXHOST] = {0};
        char service[NI_MAXSERV] = {0};
        if (getnameinfo(reinterpret_cast<const sockaddr *>(&addr), static_cast<socklen_t>(sizeof(addr)), host,
                        sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
        {
            return "[unknown]";
        }
        std::ostringstream oss;
        oss << host << ':' << service;
        return oss.str();
    }

    bool disableNagle(SOCKET socket)
    {
        const BOOL flag = TRUE;
        return setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&flag), sizeof(flag)) == 0;
    }

    void flushTcp(SOCKET socket)
    {
        if (socket == INVALID_SOCKET)
        {
            return;
        }
        const BOOL flag = TRUE;
        setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&flag), sizeof(flag));
    }

    bool setSocketTimeout(SOCKET socket, int option, DWORD timeoutMs)
    {
        return setsockopt(socket, SOL_SOCKET, option, reinterpret_cast<const char *>(&timeoutMs), sizeof(timeoutMs)) == 0;
    }

    bool recvExact(SOCKET socket, void *buffer, size_t bytes)
    {
        char *cursor = static_cast<char *>(buffer);
        size_t receivedTotal = 0;
        while (receivedTotal < bytes)
        {
            const int chunk = recv(socket, cursor + receivedTotal, static_cast<int>(bytes - receivedTotal), 0);
            if (chunk == 0)
            {
                return false;
            }
            if (chunk == SOCKET_ERROR)
            {
                const int err = WSAGetLastError();
                if (err == WSAEINTR)
                {
                    continue;
                }
                return false;
            }
            receivedTotal += static_cast<size_t>(chunk);
        }
        return true;
    }

    bool sendAll(SOCKET socket, const void *buffer, size_t bytes)
    {
        const char *cursor = static_cast<const char *>(buffer);
        size_t sentTotal = 0;
        while (sentTotal < bytes)
        {
            const int chunk = send(socket, cursor + sentTotal, static_cast<int>(bytes - sentTotal), 0);
            if (chunk == SOCKET_ERROR)
            {
                const int err = WSAGetLastError();
                if (err == WSAEINTR)
                {
                    continue;
                }
                return false;
            }
            sentTotal += static_cast<size_t>(chunk);
        }
        return true;
    }

    bool sendLengthPrefixed(SOCKET socket, const char *data, uint16_t length)
    {
        const uint16_t netLen = htons(length);
        if (!sendAll(socket, &netLen, sizeof(netLen)))
        {
            return false;
        }
        if (length == 0)
        {
            flushTcp(socket);
            return true;
        }
        if (!sendAll(socket, data, length))
        {
            return false;
        }
        flushTcp(socket);
        return true;
    }

    void udpToClientPump(ConnectionContext &context, SOCKET udpSocket)
    {
        std::vector<char> buffer(kMaxPayloadSize);
        while (context.running.load(std::memory_order_acquire))
        {
            const int received = recv(udpSocket, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received == SOCKET_ERROR)
            {
                const int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT)
                {
                    continue;
                }
                logMessage(LogLevel::Warn, context.remoteTag,
                           "UDP target recv failed, closing tunnel. WSA error=" + std::to_string(err));
                break;
            }
            if (received == 0)
            {
                logMessage(LogLevel::Info, context.remoteTag, "UDP target closed socket");
                break;
            }

            if (received > static_cast<int>(std::numeric_limits<uint16_t>::max()))
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Received UDP payload larger than framing limit; dropping packet");
                continue;
            }

            if (!sendLengthPrefixed(context.socket, buffer.data(), static_cast<uint16_t>(received)))
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Failed to forward UDP payload back to client; closing tunnel");
                break;
            }
        }

        context.running.store(false, std::memory_order_release);
    }

    void handleUdpTunnel(ConnectionContext &context)
    {
        SOCKET udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, context.remoteTag,
                       "Unable to create UDP socket, WSA error=" + std::to_string(WSAGetLastError()));
            return;
        }

        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        local.sin_port = htons(0);

        if (bind(udpSocket, reinterpret_cast<sockaddr *>(&local), sizeof(local)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, context.remoteTag,
                       "Failed to bind UDP socket, WSA error=" + std::to_string(WSAGetLastError()));
            closesocket(udpSocket);
            return;
        }

        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        target.sin_port = htons(context.targetPort);

        if (connect(udpSocket, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, context.remoteTag,
                       "Failed to connect UDP socket to target, WSA error=" + std::to_string(WSAGetLastError()));
            closesocket(udpSocket);
            return;
        }

        DWORD recvTimeoutMs = 3000;
        setSocketTimeout(udpSocket, SO_RCVTIMEO, recvTimeoutMs);

        logMessage(LogLevel::Info, context.remoteTag,
                   "UDP tunnel established to target 127.0.0.1:" + std::to_string(context.targetPort));

        std::thread downstream(udpToClientPump, std::ref(context), udpSocket);

        std::vector<char> buffer(kMaxPayloadSize);
        while (context.running.load(std::memory_order_acquire))
        {
            uint16_t netLen = 0;
            if (!recvExact(context.socket, &netLen, sizeof(netLen)))
            {
                logMessage(LogLevel::Info, context.remoteTag, "Client closed UDP tunnel");
                break;
            }
            const uint16_t len = ntohs(netLen);
            if (len == 0)
            {
                // keep-alive or handshake echo
                continue;
            }

            if (len > kMaxPayloadSize)
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Client UDP payload length exceeds limit; closing tunnel");
                break;
            }

            buffer.resize(len);
            if (!recvExact(context.socket, buffer.data(), len))
            {
                logMessage(LogLevel::Warn, context.remoteTag, "Client UDP stream ended unexpectedly");
                break;
            }

            const int sent = send(udpSocket, buffer.data(), len, 0);
            if (sent == SOCKET_ERROR || sent != len)
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Failed to forward UDP payload to target, WSA error=" +
                               std::to_string(WSAGetLastError()));
                break;
            }
        }

        context.running.store(false, std::memory_order_release);
        closesocket(udpSocket);
        if (downstream.joinable())
        {
            downstream.join();
        }
        logMessage(LogLevel::Info, context.remoteTag, "UDP tunnel closed");
    }

    void tcpTargetToClientPump(ConnectionContext &context, SOCKET targetSocket, std::atomic_bool &running)
    {
        std::vector<char> buffer(kMaxPayloadSize);
        while (context.running.load(std::memory_order_acquire) && running.load(std::memory_order_acquire))
        {
            const int received = recv(targetSocket, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received == 0)
            {
                logMessage(LogLevel::Info, context.remoteTag, "Target -> client closed by peer");
                break;
            }
            if (received == SOCKET_ERROR)
            {
                const int err = WSAGetLastError();
                if (err == WSAEINTR)
                {
                    continue;
                }
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Target -> client recv error, closing tunnel. WSA error=" + std::to_string(err));
                break;
            }

            if (received > static_cast<int>(std::numeric_limits<uint16_t>::max()))
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "TCP target payload exceeds framing limit; dropping chunk");
                continue;
            }

            if (!sendLengthPrefixed(context.socket, buffer.data(), static_cast<uint16_t>(received)))
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Target -> client send failed, closing tunnel");
                break;
            }
        }
        running.store(false, std::memory_order_release);
    }

    void handleTcpTunnel(ConnectionContext &context)
    {
        SOCKET targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (targetSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, context.remoteTag,
                       "Unable to create TCP target socket, WSA error=" + std::to_string(WSAGetLastError()));
            return;
        }

        disableNagle(targetSocket);

        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        target.sin_port = htons(context.targetPort);

        if (connect(targetSocket, reinterpret_cast<sockaddr *>(&target), sizeof(target)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, context.remoteTag,
                       "Failed to connect TCP target, WSA error=" + std::to_string(WSAGetLastError()));
            closesocket(targetSocket);
            return;
        }

        logMessage(LogLevel::Info, context.remoteTag,
                   "TCP tunnel established to target 127.0.0.1:" + std::to_string(context.targetPort));

        std::atomic_bool targetRunning{true};
        std::thread downlink(tcpTargetToClientPump, std::ref(context), targetSocket, std::ref(targetRunning));

        std::vector<char> buffer(kMaxPayloadSize);
        while (context.running.load(std::memory_order_acquire) && targetRunning.load(std::memory_order_acquire))
        {
            uint16_t netLen = 0;
            if (!recvExact(context.socket, &netLen, sizeof(netLen)))
            {
                logMessage(LogLevel::Info, context.remoteTag, "Client closed TCP tunnel");
                break;
            }
            const uint16_t len = ntohs(netLen);
            if (len == 0)
            {
                continue;
            }

            if (len > kMaxPayloadSize)
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Client TCP payload length exceeds limit; closing tunnel");
                break;
            }

            buffer.resize(len);
            if (!recvExact(context.socket, buffer.data(), len))
            {
                logMessage(LogLevel::Warn, context.remoteTag, "Client TCP stream ended unexpectedly");
                break;
            }

            if (!sendAll(targetSocket, buffer.data(), len))
            {
                logMessage(LogLevel::Warn, context.remoteTag,
                           "Failed to forward TCP payload to target");
                break;
            }
            flushTcp(targetSocket);
        }

        context.running.store(false, std::memory_order_release);
        targetRunning.store(false, std::memory_order_release);
        shutdown(targetSocket, SD_BOTH);
        closesocket(targetSocket);
        if (downlink.joinable())
        {
            downlink.join();
        }
        logMessage(LogLevel::Info, context.remoteTag, "TCP tunnel closed");
    }

    void handleClient(SOCKET clientSocket, sockaddr_storage clientAddr)
    {
        const uint64_t connId = ++g_connectionId;
        ConnectionContext context;
        context.socket = clientSocket;
        context.remoteTag = "[conn " + std::to_string(connId) + "][" + formatRemote(clientAddr) + "]";

        disableNagle(clientSocket);

        logMessage(LogLevel::Info, context.remoteTag, "Connection accepted, waiting for handshake");

        DWORD handshakeTimeoutMs = 5000;
        setSocketTimeout(clientSocket, SO_RCVTIMEO, handshakeTimeoutMs);

        ProxyHeader header{};
        if (!recvExact(clientSocket, &header, sizeof(header)))
        {
            logMessage(LogLevel::Warn, context.remoteTag, "Failed to read handshake header, closing connection");
            closesocket(clientSocket);
            return;
        }

        DWORD blockingTimeout = 0;
        setSocketTimeout(clientSocket, SO_RCVTIMEO, blockingTimeout);

        if (header.type != static_cast<uint8_t>(ProxyProtocol::UDP) &&
            header.type != static_cast<uint8_t>(ProxyProtocol::TCP))
        {
            logMessage(LogLevel::Warn, context.remoteTag, "Unsupported protocol type in handshake");
            closesocket(clientSocket);
            return;
        }

        const uint16_t declaredLen = ntohs(header.datalen);
        if (declaredLen != 0)
        {
            std::vector<char> discard(declaredLen);
            if (!recvExact(clientSocket, discard.data(), declaredLen))
            {
                logMessage(LogLevel::Warn, context.remoteTag, "Failed to read handshake payload, closing");
                closesocket(clientSocket);
                return;
            }
        }

        context.protocol = static_cast<ProxyProtocol>(header.type);
        context.targetPort = ntohs(header.target_port);

        if (context.targetPort == 0)
        {
            logMessage(LogLevel::Warn, context.remoteTag, "Handshake target port is zero, closing");
            closesocket(clientSocket);
            return;
        }

        std::string protoStr = context.protocol == ProxyProtocol::UDP ? "UDP" : "TCP";
        logMessage(LogLevel::Info, context.remoteTag,
                   "Handshake complete. Protocol=" + protoStr + ", target_port=" + std::to_string(context.targetPort));

        if (context.protocol == ProxyProtocol::UDP)
        {
            handleUdpTunnel(context);
        }
        else
        {
            handleTcpTunnel(context);
        }

        shutdown(clientSocket, SD_BOTH);
        closesocket(clientSocket);
        logMessage(LogLevel::Info, context.remoteTag, "Connection handler exited");
    }
} // namespace

int main()
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Enter IPv6 TCP listen port: " << std::flush;
    unsigned int port = 0;
    if (!(std::cin >> port) || port == 0 || port > 65535)
    {
        std::cerr << "Invalid port" << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    SOCKET listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        std::cerr << "Failed to create listen socket, WSA error=" << WSAGetLastError() << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    const int dualStack = 0;
    setsockopt(listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&dualStack), sizeof(dualStack));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(static_cast<uint16_t>(port));

    if (bind(listenSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
    {
        std::cerr << "Bind failed, WSA error=" << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return EXIT_FAILURE;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        std::cerr << "Listen failed, WSA error=" << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return EXIT_FAILURE;
    }

    logMessage(LogLevel::Info, "[server]", "Listening on [::]:" + std::to_string(port));

    while (true)
    {
        sockaddr_storage clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, reinterpret_cast<sockaddr *>(&clientAddr), &clientAddrLen);
        if (clientSocket == INVALID_SOCKET)
        {
            const int err = WSAGetLastError();
            if (err == WSAEINTR)
            {
                continue;
            }
            logMessage(LogLevel::Error, "[server]", "Accept failed, WSA error=" + std::to_string(err));
            break;
        }

        std::thread(handleClient, clientSocket, clientAddr).detach();
    }

    closesocket(listenSocket);
    WSACleanup();
    return EXIT_SUCCESS;
}
