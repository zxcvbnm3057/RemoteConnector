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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "ProxyHeader.h"

#pragma comment(lib, "Ws2_32.lib")

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr size_t kMaxPayloadSize = 65535;
    constexpr std::chrono::seconds kUdpIdleTimeout{60};
    constexpr std::chrono::seconds kUdpSweepInterval{5};

    // UDP hole punching constants
    constexpr std::chrono::seconds kHeartbeatInterval{20};
    constexpr std::chrono::seconds kMaxIdleTime{40}; // 2 * heartbeat interval
    constexpr std::chrono::milliseconds kHandshakeInterval{1000};
    constexpr int kMaxHandshakeRetries = 30;
    constexpr std::chrono::seconds kReconnectDelay{5}; // Delay before reconnection attempt

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
        TCP = 1,
        UDP_HOLE_PUNCHING = 2
    };

    struct ConfigEntry
    {
        ProxyProtocol protocol = ProxyProtocol::UDP;
        uint16_t listenPort = 0;
    };

    struct Config
    {
        bool udpOverTcp = true; // default to existing behavior
        std::vector<ConfigEntry> entries;
    };

    struct ServerEndpoint
    {
        sockaddr_in6 addr{};
        std::string display;
    };

    struct UdpTunnel
    {
        SOCKET tcpSocket = INVALID_SOCKET;
        sockaddr_storage peerAddr{};
        int peerAddrLen = 0;
        std::atomic_bool running{true};
        Clock::time_point lastActive = Clock::now();
        std::thread readerThread;
        std::thread::id readerThreadId{};
        std::string key;
        std::string tag;
    };

    struct UdpListenerState
    {
        SOCKET udpSocket = INVALID_SOCKET;
        uint16_t listenPort = 0;
        std::unordered_map<std::string, std::shared_ptr<UdpTunnel>> tunnels;
        std::mutex mutex;
        std::atomic_bool running{true};
        std::thread sweepThread;
        std::string logTag;
    };

    struct UdpHolePunchTunnel
    {
        SOCKET clientSocket = INVALID_SOCKET; // 客户端随机端口socket
        SOCKET listenSocket = INVALID_SOCKET; // 监听端口socket
        uint16_t listenPort = 0;              // 本地监听端口
        uint16_t clientPort = 0;              // 客户端随机端口
        uint16_t serverPort = 0;              // 服务端端口
        sockaddr_storage serverAddr{};        // 服务端地址
        int serverAddrLen = 0;
        std::atomic_bool running{true};
        std::atomic_bool connected{false};
        Clock::time_point lastActivity = Clock::now();
        std::thread readerThread;
        std::thread heartbeatThread;
        std::string tag;

        // Track the most recent local client for response routing
        sockaddr_storage lastLocalClient{};
        int lastLocalClientLen = 0;
        std::mutex clientMutex;
    };

    struct UdpHolePunchListenerState
    {
        SOCKET udpSocket = INVALID_SOCKET;
        uint16_t listenPort = 0;
        std::shared_ptr<UdpHolePunchTunnel> tunnel; // Single tunnel per port
        std::mutex mutex;
        std::atomic_bool running{true};
        std::string logTag;
    };

    std::atomic_bool g_running{true};
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

    std::string protocolToString(ProxyProtocol protocol)
    {
        return protocol == ProxyProtocol::UDP ? "UDP" : "TCP";
    }

    std::string formatEndpoint(const sockaddr_storage &addr, int addrLen)
    {
        char host[NI_MAXHOST] = {0};
        char service[NI_MAXSERV] = {0};
        if (getnameinfo(reinterpret_cast<const sockaddr *>(&addr), static_cast<socklen_t>(addrLen), host, sizeof(host),
                        service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) != 0)
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

    bool sendHandshake(SOCKET socket, ProxyProtocol protocol, uint16_t targetPort, const std::string &tag)
    {
        ProxyHeader header{};
        header.type = static_cast<uint8_t>(protocol);
        header.target_port = htons(targetPort);
        header.datalen = htons(0);

        if (!sendAll(socket, &header, sizeof(header)))
        {
            logMessage(LogLevel::Warn, tag, "Failed to send handshake header");
            return false;
        }
        flushTcp(socket);
        return true;
    }

    std::string trimLine(const std::string &line)
    {
        std::string result = line;
        auto commentPos = result.find('#');
        if (commentPos != std::string::npos)
        {
            result = result.substr(0, commentPos);
        }
        result.erase(result.begin(), std::find_if(result.begin(), result.end(), [](unsigned char ch)
                                                  { return !std::isspace(ch); }));
        result.erase(std::find_if(result.rbegin(), result.rend(), [](unsigned char ch)
                                  { return !std::isspace(ch); })
                         .base(),
                     result.end());
        return result;
    }

    Config loadConfig(const std::string &path)
    {
        std::ifstream file(path);
        if (!file.is_open())
        {
            throw std::runtime_error("Unable to open config file: " + path);
        }

        Config config;
        std::string line;
        int lineNumber = 0;
        enum class Section
        {
            None,
            Generic,
            Proxies
        } currentSection = Section::None;

        while (std::getline(file, line))
        {
            ++lineNumber;
            std::string trimmed = trimLine(line);

            if (trimmed.empty())
            {
                continue;
            }

            // Check for section headers
            if (trimmed.front() == '[' && trimmed.back() == ']')
            {
                std::string sectionName = trimmed.substr(1, trimmed.length() - 2);
                std::transform(sectionName.begin(), sectionName.end(), sectionName.begin(), [](unsigned char ch)
                               { return static_cast<char>(std::tolower(ch)); });

                if (sectionName == "generic")
                {
                    currentSection = Section::Generic;
                }
                else if (sectionName == "proxies")
                {
                    currentSection = Section::Proxies;
                }
                else
                {
                    throw std::runtime_error("Unknown section on line " + std::to_string(lineNumber) + ": " + sectionName);
                }
                continue;
            }

            // Parse content based on current section
            if (currentSection == Section::Generic)
            {
                const auto equalPos = trimmed.find('=');
                if (equalPos == std::string::npos)
                {
                    throw std::runtime_error("Invalid config line " + std::to_string(lineNumber) + ": " + trimmed);
                }

                std::string key = trimmed.substr(0, equalPos);
                std::string value = trimmed.substr(equalPos + 1);

                // Trim key and value
                key = trimLine(key);
                value = trimLine(value);

                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char ch)
                               { return static_cast<char>(std::tolower(ch)); });
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch)
                               { return static_cast<char>(std::tolower(ch)); });

                if (key == "udp_over_tcp")
                {
                    config.udpOverTcp = (value == "true");
                }
                else
                {
                    throw std::runtime_error("Unknown config key on line " + std::to_string(lineNumber) + ": " + key);
                }
            }
            else if (currentSection == Section::Proxies)
            {
                const auto commaPos = trimmed.find(',');
                if (commaPos == std::string::npos)
                {
                    throw std::runtime_error("Invalid proxy config line " + std::to_string(lineNumber) + ": " + trimmed);
                }

                std::string protocolStr = trimmed.substr(0, commaPos);
                std::string portStr = trimmed.substr(commaPos + 1);

                std::transform(protocolStr.begin(), protocolStr.end(), protocolStr.begin(), [](unsigned char ch)
                               { return static_cast<char>(std::tolower(ch)); });

                ConfigEntry entry;
                if (protocolStr == "udp")
                {
                    entry.protocol = ProxyProtocol::UDP;
                }
                else if (protocolStr == "tcp")
                {
                    entry.protocol = ProxyProtocol::TCP;
                }
                else
                {
                    throw std::runtime_error("Unknown protocol on line " + std::to_string(lineNumber) + ": " +
                                             protocolStr);
                }

                unsigned long portValue = std::stoul(portStr);
                if (portValue == 0 || portValue > 65535)
                {
                    throw std::runtime_error("Invalid port on line " + std::to_string(lineNumber) + ": " + portStr);
                }

                entry.listenPort = static_cast<uint16_t>(portValue);
                config.entries.push_back(entry);
            }
            else
            {
                // Legacy format support - treat as proxy entries
                const auto commaPos = trimmed.find(',');
                if (commaPos == std::string::npos)
                {
                    throw std::runtime_error("Invalid config line " + std::to_string(lineNumber) + ": " + trimmed);
                }

                std::string protocolStr = trimmed.substr(0, commaPos);
                std::string portStr = trimmed.substr(commaPos + 1);

                std::transform(protocolStr.begin(), protocolStr.end(), protocolStr.begin(), [](unsigned char ch)
                               { return static_cast<char>(std::tolower(ch)); });

                ConfigEntry entry;
                if (protocolStr == "udp")
                {
                    entry.protocol = ProxyProtocol::UDP;
                }
                else if (protocolStr == "tcp")
                {
                    entry.protocol = ProxyProtocol::TCP;
                }
                else
                {
                    throw std::runtime_error("Unknown protocol on line " + std::to_string(lineNumber) + ": " +
                                             protocolStr);
                }

                unsigned long portValue = std::stoul(portStr);
                if (portValue == 0 || portValue > 65535)
                {
                    throw std::runtime_error("Invalid port on line " + std::to_string(lineNumber) + ": " + portStr);
                }

                entry.listenPort = static_cast<uint16_t>(portValue);
                config.entries.push_back(entry);
            }
        }

        if (config.entries.empty())
        {
            throw std::runtime_error("No valid proxy entries in config file");
        }

        return config;
    }

    SOCKET connectToServer(const ServerEndpoint &endpoint, const std::string &tag)
    {
        SOCKET socketHandle = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (socketHandle == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, tag,
                       "Failed to create TCP tunnel socket, WSA error=" + std::to_string(WSAGetLastError()));
            return INVALID_SOCKET;
        }

        disableNagle(socketHandle);

        if (connect(socketHandle, reinterpret_cast<const sockaddr *>(&endpoint.addr), sizeof(endpoint.addr)) ==
            SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, tag,
                       "Failed to connect to server " + endpoint.display + ", WSA error=" +
                           std::to_string(WSAGetLastError()));
            closesocket(socketHandle);
            return INVALID_SOCKET;
        }

        logMessage(LogLevel::Info, tag, "Connected to server " + endpoint.display);
        return socketHandle;
    }

    std::string makeUdpKey(uint16_t listenPort, const sockaddr_storage &peerAddr, int peerAddrLen)
    {
        return std::to_string(listenPort) + '|' + formatEndpoint(peerAddr, peerAddrLen);
    }

    void closeUdpTunnel(UdpListenerState &state, const std::string &key, const std::shared_ptr<UdpTunnel> &tunnel,
                        const std::string &reason)
    {
        if (!tunnel)
        {
            return;
        }

        bool expected = true;
        const bool initiatedClose = tunnel->running.compare_exchange_strong(expected, false);

        if (initiatedClose)
        {
            logMessage(LogLevel::Info, tunnel->tag, "Closing UDP tunnel: " + reason);
        }

        shutdown(tunnel->tcpSocket, SD_BOTH);
        closesocket(tunnel->tcpSocket);

        if (tunnel->readerThread.joinable() && std::this_thread::get_id() != tunnel->readerThreadId)
        {
            tunnel->readerThread.join();
        }

        std::lock_guard<std::mutex> lock(state.mutex);
        auto it = state.tunnels.find(key);
        if (it != state.tunnels.end() && it->second == tunnel)
        {
            state.tunnels.erase(it);
        }
    }

    void udpTunnelReader(std::shared_ptr<UdpTunnel> tunnel, UdpListenerState *state, SOCKET udpSocket)
    {
        std::vector<char> buffer(kMaxPayloadSize);
        while (tunnel->running.load(std::memory_order_acquire))
        {
            uint16_t netLen = 0;
            if (!recvExact(tunnel->tcpSocket, &netLen, sizeof(netLen)))
            {
                logMessage(LogLevel::Info, tunnel->tag, "Server closed UDP tunnel");
                break;
            }
            const uint16_t len = ntohs(netLen);
            if (len == 0)
            {
                continue;
            }
            if (len > kMaxPayloadSize)
            {
                logMessage(LogLevel::Warn, tunnel->tag,
                           "Server sent UDP payload exceeding limit; closing tunnel");
                break;
            }

            buffer.resize(len);
            if (!recvExact(tunnel->tcpSocket, buffer.data(), len))
            {
                logMessage(LogLevel::Warn, tunnel->tag, "Server UDP payload truncated; closing tunnel");
                break;
            }

            const int sent = sendto(udpSocket, buffer.data(), len, 0,
                                    reinterpret_cast<const sockaddr *>(&tunnel->peerAddr), tunnel->peerAddrLen);
            if (sent == SOCKET_ERROR || sent != len)
            {
                logMessage(LogLevel::Warn, tunnel->tag,
                           "Failed to send UDP payload to local peer, WSA error=" +
                               std::to_string(WSAGetLastError()));
                break;
            }

            tunnel->lastActive = Clock::now();
        }

        tunnel->running.store(false, std::memory_order_release);
        tunnel->lastActive = Clock::time_point::min();
        if (state)
        {
            // Allow sweeper or sender thread to finalize cleanup.
            logMessage(LogLevel::Info, tunnel->tag, "UDP tunnel reader exiting");
        }
    }

    void udpSweeper(UdpListenerState *state)
    {
        while (state->running.load(std::memory_order_acquire) && g_running.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(kUdpSweepInterval);
            const auto now = Clock::now();

            std::vector<std::pair<std::string, std::shared_ptr<UdpTunnel>>> expired;
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                for (auto &[key, tunnel] : state->tunnels)
                {
                    if (!tunnel)
                    {
                        continue;
                    }
                    if ((now - tunnel->lastActive) >= kUdpIdleTimeout)
                    {
                        expired.emplace_back(key, tunnel);
                    }
                }
            }

            for (auto &[key, tunnel] : expired)
            {
                closeUdpTunnel(*state, key, tunnel, "Idle timeout");
            }
        }
    }

    void runUdpListener(const ConfigEntry &entry, const ServerEndpoint &serverEndpoint)
    {
        SOCKET udpSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, "[udp]",
                       "Failed to create UDP socket for port " + std::to_string(entry.listenPort) +
                           ", WSA error=" + std::to_string(WSAGetLastError()));
            return;
        }

        const int dualStack = 0;
        setsockopt(udpSocket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&dualStack), sizeof(dualStack));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(entry.listenPort);

        if (bind(udpSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, "[udp]",
                       "Failed to bind UDP port " + std::to_string(entry.listenPort) + ", WSA error=" +
                           std::to_string(WSAGetLastError()));
            closesocket(udpSocket);
            return;
        }

        UdpListenerState state;
        state.udpSocket = udpSocket;
        state.listenPort = entry.listenPort;
        state.logTag = "[udp:" + std::to_string(entry.listenPort) + ']';
        state.sweepThread = std::thread(udpSweeper, &state);

        logMessage(LogLevel::Info, state.logTag, "Listening for UDP clients");

        std::vector<char> buffer(kMaxPayloadSize);
        while (g_running.load(std::memory_order_acquire))
        {
            sockaddr_storage peerAddr{};
            int peerLen = sizeof(peerAddr);
            const int received = recvfrom(udpSocket, buffer.data(), static_cast<int>(buffer.size()), 0,
                                          reinterpret_cast<sockaddr *>(&peerAddr), &peerLen);
            if (received == SOCKET_ERROR)
            {
                const int err = WSAGetLastError();
                if (err == WSAEINTR)
                {
                    continue;
                }
                if (!g_running.load(std::memory_order_acquire))
                {
                    break;
                }
                logMessage(LogLevel::Warn, state.logTag,
                           "recvfrom failed, WSA error=" + std::to_string(err));
                continue;
            }

            const std::string peerDisplay = formatEndpoint(peerAddr, peerLen);
            const std::string key = makeUdpKey(entry.listenPort, peerAddr, peerLen);

            std::shared_ptr<UdpTunnel> tunnel;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                auto it = state.tunnels.find(key);
                if (it != state.tunnels.end())
                {
                    tunnel = it->second;
                }
            }

            if (!tunnel)
            {
                const std::string tunnelTag = state.logTag + "[client " + peerDisplay + "]";
                SOCKET tcpSocket = connectToServer(serverEndpoint, tunnelTag);
                if (tcpSocket == INVALID_SOCKET)
                {
                    logMessage(LogLevel::Warn, tunnelTag, "Unable to create tunnel; dropping packet");
                    continue;
                }

                if (!sendHandshake(tcpSocket, ProxyProtocol::UDP, entry.listenPort, tunnelTag))
                {
                    logMessage(LogLevel::Warn, tunnelTag, "Handshake failed; closing tunnel");
                    closesocket(tcpSocket);
                    continue;
                }

                tunnel = std::make_shared<UdpTunnel>();
                tunnel->tcpSocket = tcpSocket;
                tunnel->peerAddr = peerAddr;
                tunnel->peerAddrLen = peerLen;
                tunnel->lastActive = Clock::now();
                tunnel->key = key;
                tunnel->tag = tunnelTag;

                tunnel->readerThread = std::thread(udpTunnelReader, tunnel, &state, udpSocket);
                tunnel->readerThreadId = tunnel->readerThread.get_id();

                {
                    std::lock_guard<std::mutex> lock(state.mutex);
                    state.tunnels[key] = tunnel;
                }

                logMessage(LogLevel::Info, tunnel->tag,
                           "UDP tunnel established -> server " + serverEndpoint.display +
                               ", target_port=" + std::to_string(entry.listenPort));
            }

            if (!tunnel->running.load(std::memory_order_acquire))
            {
                closeUdpTunnel(state, key, tunnel, "Reset inactive tunnel");
                tunnel.reset();
                continue;
            }

            if (received > static_cast<int>(std::numeric_limits<uint16_t>::max()))
            {
                logMessage(LogLevel::Warn, tunnel->tag,
                           "Local UDP payload exceeds framing limit; dropping");
                continue;
            }

            if (!sendLengthPrefixed(tunnel->tcpSocket, buffer.data(), static_cast<uint16_t>(received)))
            {
                logMessage(LogLevel::Warn, tunnel->tag,
                           "Failed to forward UDP payload to server; closing tunnel");
                closeUdpTunnel(state, key, tunnel, "Upstream send failure");
                continue;
            }

            tunnel->lastActive = Clock::now();
        }

        state.running.store(false, std::memory_order_release);

        {
            std::vector<std::pair<std::string, std::shared_ptr<UdpTunnel>>> tunnelsCopy;
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                for (auto &kv : state.tunnels)
                {
                    tunnelsCopy.emplace_back(kv.first, kv.second);
                }
            }
            for (auto &[key, tunnel] : tunnelsCopy)
            {
                closeUdpTunnel(state, key, tunnel, "Client shutting down");
            }
        }

        if (state.sweepThread.joinable())
        {
            state.sweepThread.join();
        }

        closesocket(udpSocket);
        logMessage(LogLevel::Info, state.logTag, "UDP listener stopped");
    }

    void tcpDownlink(std::atomic_bool &running, SOCKET serverSocket, SOCKET localSocket, const std::string &tag)
    {
        std::vector<char> buffer(kMaxPayloadSize);
        while (running.load(std::memory_order_acquire))
        {
            uint16_t netLen = 0;
            if (!recvExact(serverSocket, &netLen, sizeof(netLen)))
            {
                logMessage(LogLevel::Info, tag, "Server closed TCP tunnel");
                break;
            }
            const uint16_t len = ntohs(netLen);
            if (len == 0)
            {
                continue;
            }
            if (len > kMaxPayloadSize)
            {
                logMessage(LogLevel::Warn, tag, "Server TCP payload exceeds limit; closing tunnel");
                break;
            }

            buffer.resize(len);
            if (!recvExact(serverSocket, buffer.data(), len))
            {
                logMessage(LogLevel::Warn, tag, "Server TCP payload truncated; closing tunnel");
                break;
            }

            if (!sendAll(localSocket, buffer.data(), len))
            {
                logMessage(LogLevel::Warn, tag, "Failed to forward TCP payload to local client");
                break;
            }
            flushTcp(localSocket);
        }

        running.store(false, std::memory_order_release);
    }

    void runTcpListener(const ConfigEntry &entry, const ServerEndpoint &serverEndpoint)
    {
        SOCKET listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, "[tcp]",
                       "Failed to create listen socket for port " + std::to_string(entry.listenPort) +
                           ", WSA error=" + std::to_string(WSAGetLastError()));
            return;
        }

        const int dualStack = 0;
        setsockopt(listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&dualStack), sizeof(dualStack));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(entry.listenPort);

        if (bind(listenSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, "[tcp]",
                       "Failed to bind TCP port " + std::to_string(entry.listenPort) + ", WSA error=" +
                           std::to_string(WSAGetLastError()));
            closesocket(listenSocket);
            return;
        }

        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, "[tcp]",
                       "Failed to listen on TCP port " + std::to_string(entry.listenPort) + ", WSA error=" +
                           std::to_string(WSAGetLastError()));
            closesocket(listenSocket);
            return;
        }

        const std::string logTag = "[tcp:" + std::to_string(entry.listenPort) + ']';
        logMessage(LogLevel::Info, logTag, "Listening for TCP clients");

        while (g_running.load(std::memory_order_acquire))
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
                if (!g_running.load(std::memory_order_acquire))
                {
                    break;
                }
                logMessage(LogLevel::Warn, logTag,
                           "accept failed, WSA error=" + std::to_string(err));
                continue;
            }

            disableNagle(clientSocket);

            const std::string clientDisplay = formatEndpoint(clientAddr, clientAddrLen);
            const std::string tunnelTag = logTag + "[client " + clientDisplay + "]";

            SOCKET serverSocket = connectToServer(serverEndpoint, tunnelTag);
            if (serverSocket == INVALID_SOCKET)
            {
                logMessage(LogLevel::Warn, tunnelTag, "Unable to connect to server; closing local client");
                closesocket(clientSocket);
                continue;
            }

            if (!sendHandshake(serverSocket, ProxyProtocol::TCP, entry.listenPort, tunnelTag))
            {
                logMessage(LogLevel::Warn, tunnelTag, "Handshake failed; closing tunnel");
                closesocket(serverSocket);
                closesocket(clientSocket);
                continue;
            }

            logMessage(LogLevel::Info, tunnelTag,
                       "TCP tunnel established -> server " + serverEndpoint.display +
                           ", target_port=" + std::to_string(entry.listenPort));

            std::atomic_bool running{true};
            std::thread downlink(tcpDownlink, std::ref(running), serverSocket, clientSocket, tunnelTag);

            std::vector<char> buffer(kMaxPayloadSize);
            while (running.load(std::memory_order_acquire) && g_running.load(std::memory_order_acquire))
            {
                const int received = recv(clientSocket, buffer.data(), static_cast<int>(buffer.size()), 0);
                if (received == 0)
                {
                    logMessage(LogLevel::Info, tunnelTag, "Local TCP client closed connection");
                    break;
                }
                if (received == SOCKET_ERROR)
                {
                    const int err = WSAGetLastError();
                    if (err == WSAEINTR)
                    {
                        continue;
                    }
                    logMessage(LogLevel::Warn, tunnelTag,
                               "recv from local client failed, WSA error=" + std::to_string(err));
                    break;
                }

                if (received > static_cast<int>(std::numeric_limits<uint16_t>::max()))
                {
                    logMessage(LogLevel::Warn, tunnelTag,
                               "Local TCP payload exceeds framing limit; closing tunnel");
                    break;
                }

                if (!sendLengthPrefixed(serverSocket, buffer.data(), static_cast<uint16_t>(received)))
                {
                    logMessage(LogLevel::Warn, tunnelTag,
                               "Failed to forward TCP payload to server");
                    break;
                }
            }

            running.store(false, std::memory_order_release);
            shutdown(serverSocket, SD_BOTH);
            shutdown(clientSocket, SD_BOTH);

            if (downlink.joinable())
            {
                downlink.join();
            }

            closesocket(serverSocket);
            closesocket(clientSocket);
            logMessage(LogLevel::Info, tunnelTag, "TCP tunnel closed");
        }

        closesocket(listenSocket);
        logMessage(LogLevel::Info, logTag, "TCP listener stopped");
    }

    // UDP Hole Punching functions
    uint16_t getRandomPort()
    {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint16_t> dis(49152, 65535); // Dynamic port range
        return dis(gen);
    }

    bool sendUdpHolePunchPacket(SOCKET socket, const sockaddr *addr, int addrLen, UdpHolePunchPacketType type, const char *data = nullptr, uint16_t dataLen = 0)
    {
        UdpHolePunchPacket packet;
        packet.type = type;
        packet.timestamp = htonl(static_cast<uint32_t>(std::time(nullptr)));
        packet.data_len = htons(dataLen);

        std::vector<char> buffer(sizeof(packet) + dataLen);
        std::memcpy(buffer.data(), &packet, sizeof(packet));
        if (data && dataLen > 0)
        {
            std::memcpy(buffer.data() + sizeof(packet), data, dataLen);
        }

        int sent = sendto(socket, buffer.data(), static_cast<int>(buffer.size()), 0, addr, addrLen);
        return sent == static_cast<int>(buffer.size());
    }

    bool sendTcpHandshakeWithPort(SOCKET socket, ProxyProtocol protocol, uint16_t targetPort, uint16_t clientPort, const std::string &tag)
    {
        ProxyHeader header{};
        header.type = static_cast<uint8_t>(protocol);
        header.target_port = htons(targetPort);
        header.datalen = htons(0);
        header.client_port = htons(clientPort);

        if (!sendAll(socket, &header, sizeof(header)))
        {
            logMessage(LogLevel::Warn, tag, "Failed to send handshake header");
            return false;
        }
        flushTcp(socket);
        return true;
    }

    bool performUdpHolePunching(std::shared_ptr<UdpHolePunchTunnel> tunnel, const ServerEndpoint &serverEndpoint)
    {
        // Create TCP connection for handshake
        SOCKET tcpSocket = connectToServer(serverEndpoint, tunnel->tag);
        if (tcpSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, tunnel->tag, "Failed to connect to server for handshake");
            return false;
        }

        // Send TCP handshake with client port
        if (!sendTcpHandshakeWithPort(tcpSocket, ProxyProtocol::UDP_HOLE_PUNCHING, tunnel->listenPort, tunnel->clientPort, tunnel->tag))
        {
            logMessage(LogLevel::Error, tunnel->tag, "Failed to send handshake");
            closesocket(tcpSocket);
            return false;
        }

        // Receive server response with server port
        ProxyHeader response{};
        if (!recvExact(tcpSocket, &response, sizeof(response)))
        {
            logMessage(LogLevel::Error, tunnel->tag, "Failed to receive handshake response");
            closesocket(tcpSocket);
            return false;
        }

        tunnel->serverPort = ntohs(response.target_port);
        closesocket(tcpSocket);

        // Setup server address with received port
        std::memcpy(&tunnel->serverAddr, &serverEndpoint.addr, sizeof(serverEndpoint.addr));
        reinterpret_cast<sockaddr_in6 *>(&tunnel->serverAddr)->sin6_port = htons(tunnel->serverPort);
        tunnel->serverAddrLen = sizeof(sockaddr_in6);

        logMessage(LogLevel::Info, tunnel->tag,
                   "Starting UDP hole punching: client_port=" + std::to_string(tunnel->clientPort) +
                       ", server_port=" + std::to_string(tunnel->serverPort));

        // Start sending handshake packets
        // The reader thread will receive handshake/ACK from server and set connected=true
        int retries = 0;
        while (tunnel->running.load(std::memory_order_acquire) && !tunnel->connected.load(std::memory_order_acquire) && retries < kMaxHandshakeRetries)
        {
            if (!sendUdpHolePunchPacket(tunnel->clientSocket,
                                        reinterpret_cast<sockaddr *>(&tunnel->serverAddr),
                                        tunnel->serverAddrLen,
                                        UdpHolePunchPacketType::HANDSHAKE))
            {
                logMessage(LogLevel::Warn, tunnel->tag, "Failed to send handshake packet");
            }

            // Update activity time to prevent idle timeout during handshake
            tunnel->lastActivity = Clock::now();

            std::this_thread::sleep_for(kHandshakeInterval);
            retries++;
        }

        if (!tunnel->connected.load(std::memory_order_acquire))
        {
            logMessage(LogLevel::Error, tunnel->tag, "UDP hole punching handshake timeout");
            return false;
        }

        return true;
    }

    void udpHolePunchHeartbeat(std::shared_ptr<UdpHolePunchTunnel> tunnel)
    {
        while (tunnel->running.load(std::memory_order_acquire) && tunnel->connected.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(kHeartbeatInterval);

            if (!tunnel->running.load(std::memory_order_acquire) || !tunnel->connected.load(std::memory_order_acquire))
            {
                break;
            }

            // Check if we've been idle too long
            auto now = Clock::now();
            if ((now - tunnel->lastActivity) > kMaxIdleTime)
            {
                logMessage(LogLevel::Warn, tunnel->tag, "UDP hole punch tunnel idle timeout, will trigger reconnection");
                tunnel->connected.store(false, std::memory_order_release);
                break;
            }

            // Send heartbeat
            if (!sendUdpHolePunchPacket(tunnel->clientSocket,
                                        reinterpret_cast<sockaddr *>(&tunnel->serverAddr),
                                        tunnel->serverAddrLen,
                                        UdpHolePunchPacketType::HEARTBEAT))
            {
                logMessage(LogLevel::Warn, tunnel->tag, "Failed to send heartbeat");
            }
        }
    }

    void udpHolePunchTunnelReader(std::shared_ptr<UdpHolePunchTunnel> tunnel)
    {
        std::vector<char> buffer(kMaxPayloadSize);
        while (tunnel->running.load(std::memory_order_acquire))
        {
            sockaddr_storage fromAddr{};
            int fromLen = sizeof(fromAddr);

            int received = recvfrom(tunnel->clientSocket, buffer.data(), static_cast<int>(buffer.size()), 0,
                                    reinterpret_cast<sockaddr *>(&fromAddr), &fromLen);

            if (received == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                if (err == WSAEINTR || err == WSAETIMEDOUT)
                {
                    continue;
                }
                if (tunnel->running.load(std::memory_order_acquire))
                {
                    logMessage(LogLevel::Warn, tunnel->tag, "UDP receive failed, WSA error=" + std::to_string(err));
                }
                break;
            }

            tunnel->lastActivity = Clock::now();

            // Check if this is a control packet
            if (received >= static_cast<int>(sizeof(UdpHolePunchPacket)))
            {
                UdpHolePunchPacket *packet = reinterpret_cast<UdpHolePunchPacket *>(buffer.data());

                // Handle HANDSHAKE from server (mutual hole punching)
                if (packet->type == UdpHolePunchPacketType::HANDSHAKE && !tunnel->connected.load(std::memory_order_acquire))
                {
                    logMessage(LogLevel::Info, tunnel->tag, "Received UDP handshake from server, replying");
                    // Reply with our own handshake to complete the punch
                    sendUdpHolePunchPacket(tunnel->clientSocket,
                                           reinterpret_cast<sockaddr *>(&fromAddr),
                                           fromLen,
                                           UdpHolePunchPacketType::HANDSHAKE);
                    continue;
                }
                // Handle ACK from server (connection established)
                else if (packet->type == UdpHolePunchPacketType::ACK && !tunnel->connected.load(std::memory_order_acquire))
                {
                    logMessage(LogLevel::Info, tunnel->tag,
                               "UDP hole punching connected (proxy port " +
                                   std::to_string(tunnel->listenPort) + ")");
                    tunnel->connected.store(true, std::memory_order_release);

                    // Start heartbeat thread
                    tunnel->heartbeatThread = std::thread(udpHolePunchHeartbeat, tunnel);
                    continue;
                }
                else if (packet->type == UdpHolePunchPacketType::HEARTBEAT)
                {
                    // Server heartbeat response, just update activity time
                    continue;
                }
            }

            // Forward data to the most recent local client
            if (tunnel->connected.load(std::memory_order_acquire))
            {
                std::lock_guard<std::mutex> lock(tunnel->clientMutex);
                if (tunnel->lastLocalClientLen > 0)
                {
                    int sent = sendto(tunnel->listenSocket, buffer.data(), received, 0,
                                      reinterpret_cast<sockaddr *>(&tunnel->lastLocalClient), tunnel->lastLocalClientLen);
                    if (sent == SOCKET_ERROR)
                    {
                        logMessage(LogLevel::Warn, tunnel->tag, "Failed to forward data to local client");
                    }
                }
            }
        }
    }

    void closeUdpHolePunchTunnel(std::shared_ptr<UdpHolePunchTunnel> tunnel, const std::string &reason)
    {
        if (!tunnel)
        {
            return;
        }

        logMessage(LogLevel::Info, tunnel->tag, "Closing UDP hole punch tunnel: " + reason);

        tunnel->running.store(false, std::memory_order_release);

        if (tunnel->readerThread.joinable())
        {
            tunnel->readerThread.join();
        }

        if (tunnel->heartbeatThread.joinable())
        {
            tunnel->heartbeatThread.join();
        }

        if (tunnel->clientSocket != INVALID_SOCKET)
        {
            closesocket(tunnel->clientSocket);
        }
    }

    void resetUdpHolePunchTunnelForReconnect(std::shared_ptr<UdpHolePunchTunnel> tunnel)
    {
        if (!tunnel)
        {
            return;
        }

        logMessage(LogLevel::Info, tunnel->tag, "Resetting tunnel for reconnection");

        // Disconnect state but keep running
        tunnel->connected.store(false, std::memory_order_release);

        // Stop and wait for heartbeat thread if it exists
        if (tunnel->heartbeatThread.joinable())
        {
            tunnel->heartbeatThread.join();
        }

        // Close and recreate client socket
        if (tunnel->clientSocket != INVALID_SOCKET)
        {
            closesocket(tunnel->clientSocket);
        }

        tunnel->clientSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (tunnel->clientSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, tunnel->tag, "Failed to recreate client socket for reconnection");
            return;
        }

        // Bind to random port
        sockaddr_in6 clientAddr{};
        clientAddr.sin6_family = AF_INET6;
        clientAddr.sin6_addr = in6addr_any;
        clientAddr.sin6_port = 0; // Let system choose port

        if (bind(tunnel->clientSocket, reinterpret_cast<sockaddr *>(&clientAddr), sizeof(clientAddr)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, tunnel->tag, "Failed to bind client socket for reconnection");
            closesocket(tunnel->clientSocket);
            tunnel->clientSocket = INVALID_SOCKET;
            return;
        }

        // Get assigned port
        int addrLen = sizeof(clientAddr);
        if (getsockname(tunnel->clientSocket, reinterpret_cast<sockaddr *>(&clientAddr), &addrLen) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, tunnel->tag, "Failed to get client socket port for reconnection");
            closesocket(tunnel->clientSocket);
            tunnel->clientSocket = INVALID_SOCKET;
            return;
        }
        tunnel->clientPort = ntohs(clientAddr.sin6_port);

        // Set socket timeout
        DWORD timeoutMs = 3000;
        setSocketTimeout(tunnel->clientSocket, SO_RCVTIMEO, timeoutMs);

        // Reset activity time
        tunnel->lastActivity = Clock::now();

        logMessage(LogLevel::Info, tunnel->tag, "Tunnel reset complete, new client_port=" + std::to_string(tunnel->clientPort));
    }

    void udpHolePunchConnectionManager(std::shared_ptr<UdpHolePunchTunnel> tunnel, const ServerEndpoint &serverEndpoint)
    {
        while (tunnel->running.load(std::memory_order_acquire))
        {
            // Attempt connection
            logMessage(LogLevel::Info, tunnel->tag, "Attempting UDP hole punching connection");
            
            if (performUdpHolePunching(tunnel, serverEndpoint))
            {
                logMessage(LogLevel::Info, tunnel->tag, "UDP hole punching connection established");
                
                // Wait for connection to fail (connected will be set to false on timeout or error)
                // Keep checking every second to allow quick response to shutdown
                while (tunnel->running.load(std::memory_order_acquire) && tunnel->connected.load(std::memory_order_acquire))
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                
                if (!tunnel->running.load(std::memory_order_acquire))
                {
                    // Shutdown requested, exit
                    break;
                }
                
                logMessage(LogLevel::Warn, tunnel->tag, "UDP hole punching connection lost, will retry");
            }
            else
            {
                logMessage(LogLevel::Error, tunnel->tag, "UDP hole punching connection failed, will retry");
            }
            
            // Wait before reconnecting
            logMessage(LogLevel::Info, tunnel->tag, "Waiting " + std::to_string(kReconnectDelay.count()) + " seconds before reconnection");
            
            auto waitStart = Clock::now();
            while (tunnel->running.load(std::memory_order_acquire) && 
                   (Clock::now() - waitStart) < kReconnectDelay)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            
            if (!tunnel->running.load(std::memory_order_acquire))
            {
                // Shutdown requested during wait, exit
                break;
            }
            
            // Reset tunnel for reconnection
            resetUdpHolePunchTunnelForReconnect(tunnel);
            
            if (tunnel->clientSocket == INVALID_SOCKET)
            {
                // Failed to reset, cannot retry
                logMessage(LogLevel::Error, tunnel->tag, "Failed to reset tunnel for reconnection");
                tunnel->running.store(false, std::memory_order_release);
                break;
            }
        }
        
        logMessage(LogLevel::Info, tunnel->tag, "UDP hole punching connection manager exited");
    }

    void runUdpHolePunchingListener(const ConfigEntry &entry, const ServerEndpoint &serverEndpoint)
    {
        SOCKET udpSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (udpSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, "[udp-hp]",
                       "Failed to create UDP socket for port " + std::to_string(entry.listenPort) +
                           ", WSA error=" + std::to_string(WSAGetLastError()));
            return;
        }

        const int dualStack = 0;
        setsockopt(udpSocket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&dualStack), sizeof(dualStack));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(entry.listenPort);

        if (bind(udpSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, "[udp-hp]",
                       "Failed to bind UDP port " + std::to_string(entry.listenPort) + ", WSA error=" +
                           std::to_string(WSAGetLastError()));
            closesocket(udpSocket);
            return;
        }

        UdpHolePunchListenerState state;
        state.udpSocket = udpSocket;
        state.listenPort = entry.listenPort;
        state.logTag = "[udp-hp:" + std::to_string(entry.listenPort) + ']';

        logMessage(LogLevel::Info, state.logTag, "Listening for UDP clients (hole punching mode)");

        // Create tunnel immediately on startup
        auto tunnel = std::make_shared<UdpHolePunchTunnel>();
        tunnel->listenPort = entry.listenPort;
        tunnel->listenSocket = udpSocket;
        tunnel->tag = state.logTag;
        tunnel->lastActivity = Clock::now();

        // Create client socket with random port
        tunnel->clientSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (tunnel->clientSocket == INVALID_SOCKET)
        {
            logMessage(LogLevel::Error, state.logTag, "Failed to create client socket");
            closesocket(udpSocket);
            return;
        }

        // Bind to random port
        sockaddr_in6 clientAddr{};
        clientAddr.sin6_family = AF_INET6;
        clientAddr.sin6_addr = in6addr_any;
        clientAddr.sin6_port = 0; // Let system choose port

        if (bind(tunnel->clientSocket, reinterpret_cast<sockaddr *>(&clientAddr), sizeof(clientAddr)) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, state.logTag, "Failed to bind client socket");
            closesocket(tunnel->clientSocket);
            closesocket(udpSocket);
            return;
        }

        // Get assigned port
        int addrLen = sizeof(clientAddr);
        if (getsockname(tunnel->clientSocket, reinterpret_cast<sockaddr *>(&clientAddr), &addrLen) == SOCKET_ERROR)
        {
            logMessage(LogLevel::Error, state.logTag, "Failed to get client socket port");
            closesocket(tunnel->clientSocket);
            closesocket(udpSocket);
            return;
        }
        tunnel->clientPort = ntohs(clientAddr.sin6_port);

        // Set socket timeout
        DWORD timeoutMs = 3000;
        setSocketTimeout(tunnel->clientSocket, SO_RCVTIMEO, timeoutMs);

        state.tunnel = tunnel;

        // Start reader thread
        tunnel->readerThread = std::thread(udpHolePunchTunnelReader, tunnel);

        // Start connection manager thread that handles connection and reconnection
        std::thread connectionManagerThread(udpHolePunchConnectionManager, tunnel, serverEndpoint);

        logMessage(LogLevel::Info, tunnel->tag,
                   "UDP hole punch tunnel initiated -> server " + serverEndpoint.display +
                       ", client_port=" + std::to_string(tunnel->clientPort));

        // Main loop: forward local UDP traffic to server
        std::vector<char> buffer(kMaxPayloadSize);
        while (g_running.load(std::memory_order_acquire) && tunnel->running.load(std::memory_order_acquire))
        {
            sockaddr_storage peerAddr{};
            int peerLen = sizeof(peerAddr);
            const int received = recvfrom(udpSocket, buffer.data(), static_cast<int>(buffer.size()), 0,
                                          reinterpret_cast<sockaddr *>(&peerAddr), &peerLen);
            if (received == SOCKET_ERROR)
            {
                const int err = WSAGetLastError();
                if (err == WSAEINTR)
                {
                    continue;
                }
                if (!g_running.load(std::memory_order_acquire))
                {
                    break;
                }
                logMessage(LogLevel::Warn, state.logTag,
                           "recvfrom failed, WSA error=" + std::to_string(err));
                continue;
            }

            // Update last local client for response routing
            {
                std::lock_guard<std::mutex> lock(tunnel->clientMutex);
                tunnel->lastLocalClient = peerAddr;
                tunnel->lastLocalClientLen = peerLen;
            }

            // Forward data to server if connected
            if (tunnel->connected.load(std::memory_order_acquire))
            {
                tunnel->lastActivity = Clock::now();
                int sent = sendto(tunnel->clientSocket, buffer.data(), received, 0,
                                  reinterpret_cast<sockaddr *>(&tunnel->serverAddr), tunnel->serverAddrLen);
                if (sent == SOCKET_ERROR)
                {
                    logMessage(LogLevel::Warn, tunnel->tag, "Failed to forward data to server");
                }
            }
        }

        state.running.store(false, std::memory_order_release);

        // Clean up tunnel
        if (state.tunnel)
        {
            closeUdpHolePunchTunnel(state.tunnel, "Client shutting down");
        }

        // Wait for connection manager thread to complete
        if (connectionManagerThread.joinable())
        {
            connectionManagerThread.join();
        }

        closesocket(udpSocket);
        logMessage(LogLevel::Info, state.logTag, "UDP hole punching listener stopped");
    }

    BOOL WINAPI consoleHandler(DWORD signal)
    {
        if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT)
        {
            g_running.store(false, std::memory_order_release);
            return TRUE;
        }
        return FALSE;
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

    SetConsoleCtrlHandler(consoleHandler, TRUE);

    std::string configPath = "client_config.conf";
    std::cout << "Enter path to config file (default client_config.conf): " << std::flush;
    std::string inputPath;
    std::getline(std::cin, inputPath);
    if (!inputPath.empty())
    {
        configPath = inputPath;
    }

    Config config;
    try
    {
        config = loadConfig(configPath);
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Failed to load config: " << ex.what() << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    std::cout << "Enter server IPv6 address: " << std::flush;
    std::string serverAddress;
    std::getline(std::cin, serverAddress);
    if (serverAddress.empty())
    {
        std::cerr << "Server IPv6 address is required" << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    std::cout << "Enter server TCP port: " << std::flush;
    std::string serverPortStr;
    std::getline(std::cin, serverPortStr);
    unsigned long serverPortValue = 0;
    try
    {
        serverPortValue = std::stoul(serverPortStr);
    }
    catch (...)
    {
        serverPortValue = 0;
    }
    if (serverPortValue == 0 || serverPortValue > 65535)
    {
        std::cerr << "Invalid server port" << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    ServerEndpoint serverEndpoint;
    serverEndpoint.addr.sin6_family = AF_INET6;
    serverEndpoint.addr.sin6_port = htons(static_cast<uint16_t>(serverPortValue));
    serverEndpoint.addr.sin6_flowinfo = 0;
    serverEndpoint.addr.sin6_scope_id = 0;

    if (inet_pton(AF_INET6, serverAddress.c_str(), &serverEndpoint.addr.sin6_addr) != 1)
    {
        std::cerr << "Invalid IPv6 address" << std::endl;
        WSACleanup();
        return EXIT_FAILURE;
    }

    serverEndpoint.display = '[' + serverAddress + "]:" + std::to_string(serverPortValue);

    logMessage(LogLevel::Info, "[client]", "Loaded " + std::to_string(config.entries.size()) + " config entries");
    logMessage(LogLevel::Info, "[client]", "UDP mode: " + std::string(config.udpOverTcp ? "UDP over TCP" : "UDP hole punching"));

    std::vector<std::thread> workers;
    workers.reserve(config.entries.size());
    for (const auto &entry : config.entries)
    {
        if (entry.protocol == ProxyProtocol::UDP)
        {
            if (config.udpOverTcp)
            {
                workers.emplace_back(runUdpListener, entry, serverEndpoint);
            }
            else
            {
                workers.emplace_back(runUdpHolePunchingListener, entry, serverEndpoint);
            }
        }
        else
        {
            workers.emplace_back(runTcpListener, entry, serverEndpoint);
        }
    }

    for (auto &worker : workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }

    WSACleanup();
    logMessage(LogLevel::Info, "[client]", "Exited cleanly");
    return EXIT_SUCCESS;
}
