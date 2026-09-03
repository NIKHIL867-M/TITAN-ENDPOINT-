#include "network_monitor.h"
#include "protocol_decoder.h"

// network_monitor.h already pulls in winsock2/ws2tcpip/iphlpapi in correct order.
// Add remaining needed headers here:
// winternl.h intentionally omitted: conflicts with /permissive- NTSTATUS typedef.
// PROCESS_BASIC_INFORMATION replaced with local PBI struct inside functions.
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cwctype>       // std::iswspace

// Net headers (platform pack ordering matters under MSVC)
#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ether_type; // big-endian
};
struct Ipv4Header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
};
struct Ipv6Header {
    uint32_t ver_tc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
};
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset; // upper 4 bits = header len in 32-bit words
    uint8_t  flags;       // SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
struct IcmpHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};
#pragma pack(pop)

static constexpr uint16_t kEtherTypeIPv4 = 0x0800;
static constexpr uint16_t kEtherTypeArp = 0x0806;
static constexpr uint16_t kEtherTypeIPv6 = 0x86DD;
static constexpr uint16_t kEtherTypeVlan = 0x8100;
static constexpr uint16_t kEtherTypeQinQ = 0x88A8;

// TCP flag bits
static constexpr uint8_t kTcpSyn = 0x02;
static constexpr uint8_t kTcpAck = 0x10;
static constexpr uint8_t kTcpFin = 0x01;
static constexpr uint8_t kTcpRst = 0x04;

namespace titan {

    namespace {
        pcap_t* OpenConfiguredCapture(const char* device, int snaplen,
            int promiscuous, int timeout_ms, char* error_buffer) {
            pcap_t* handle = pcap_create(device, error_buffer);
            if (!handle) return nullptr;

            constexpr int kCaptureBufferBytes = 2 * 1024 * 1024;
            if (pcap_set_snaplen(handle, snaplen) != 0 ||
                pcap_set_promisc(handle, promiscuous) != 0 ||
                pcap_set_timeout(handle, timeout_ms) != 0 ||
                pcap_set_buffer_size(handle, kCaptureBufferBytes) != 0) {
                const std::string error = pcap_geterr(handle);
                pcap_close(handle);
                strncpy_s(error_buffer, PCAP_ERRBUF_SIZE,
                    error.c_str(), _TRUNCATE);
                return nullptr;
            }

            const int result = pcap_activate(handle);
            if (result < 0) {
                const std::string error = pcap_geterr(handle);
                pcap_close(handle);
                strncpy_s(error_buffer, PCAP_ERRBUF_SIZE,
                    error.c_str(), _TRUNCATE);
                return nullptr;
            }
            return handle;
        }
    }

    // ============================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ============================================================================

    NetworkMonitor::NetworkMonitor(AsyncLogger& logger,
        const std::wstring& log_directory)
        : logger_(logger),
          raw_capture_directory_(
              std::filesystem::path(log_directory) / L"raw_pcap")
    {
        // Raw segments are deliberately session-scoped. Unique names make JSON
        // references safe from same-name reuse, while removing only TITAN-owned
        // adapter_*.pcap files at the next start preserves the prior bounded
        // two-segments-per-adapter policy instead of accumulating across runs.
        std::error_code error;
        std::filesystem::create_directories(raw_capture_directory_, error);
        for (const auto& entry : std::filesystem::directory_iterator(raw_capture_directory_, error)) {
            if (error) break;
            const auto name = entry.path().filename().string();
            if (entry.is_regular_file() && entry.path().extension() == ".pcap" &&
                name.rfind("adapter_", 0) == 0) {
                std::filesystem::remove(entry.path(), error);
                if (error) {
                    raw_capture_failures_.fetch_add(1, std::memory_order_relaxed);
                    error.clear();
                }
            }
        }
        BuildPortAppMap();
    }

    NetworkMonitor::~NetworkMonitor() {
        if (running_.load()) Stop();
    }

    bool NetworkMonitor::OpenRawDumper(AdapterCtx& adapter) {
        if (!adapter.handle) return false;
        std::error_code error;
        std::filesystem::create_directories(
            raw_capture_directory_, error);
        if (error) {
            raw_capture_failures_.fetch_add(1,
                std::memory_order_relaxed);
            return false;
        }
        if (adapter.raw_base.empty()) {
            adapter.raw_base = raw_capture_directory_ /
                ("adapter_" + std::to_string(
                    std::hash<std::string>{}(adapter.name)));
            const auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            adapter.raw_session = std::to_string(GetCurrentProcessId()) + "_" + std::to_string(epoch);
        }
        const auto path = std::filesystem::path(
            adapter.raw_base.string() + "_" + adapter.raw_session + "_" +
            std::to_string(adapter.raw_generation++) + ".pcap");
        adapter.dumper = pcap_dump_open(
            adapter.handle, path.string().c_str());
        if (!adapter.dumper) {
            raw_capture_failures_.fetch_add(1,
                std::memory_order_relaxed);
            ConsoleLogger::LogWarning(
                std::string("Raw PCAP disabled for adapter: ") +
                pcap_geterr(adapter.handle));
            return false;
        }
        adapter.raw_bytes = 24;
        adapter.raw_current_path = path;
        adapter.raw_retained_paths.push_back(path);
        while (adapter.raw_retained_paths.size() > 2) {
            const auto expired = adapter.raw_retained_paths.front();
            adapter.raw_retained_paths.pop_front();
            std::filesystem::remove(expired, error);
        }
        return true;
    }

    void NetworkMonitor::RotateRawDumperIfNeeded(AdapterCtx& adapter,
        uint32_t incoming_bytes) {
        if (!adapter.dumper) return;
        if (adapter.raw_bytes + incoming_bytes <= kRawPcapBytes) {
            adapter.raw_bytes += incoming_bytes;
            return;
        }
        pcap_dump_flush(adapter.dumper);
        pcap_dump_close(adapter.dumper);
        adapter.dumper = nullptr;
        OpenRawDumper(adapter);
        adapter.raw_bytes += incoming_bytes;
    }

    // ============================================================================
    // PORT → APP LAYER MAP
    // ============================================================================

    void NetworkMonitor::BuildPortAppMap() {
        port_app_map_ = {
            {uint16_t{80},   AppLayer::HTTP},
            {uint16_t{8080}, AppLayer::HTTP},
            {uint16_t{8000}, AppLayer::HTTP},
            {uint16_t{443},  AppLayer::HTTPS_TLS},
            {uint16_t{8443}, AppLayer::HTTPS_TLS},
            {uint16_t{53},   AppLayer::DNS},
            {uint16_t{3389}, AppLayer::RDP},
            {uint16_t{445},  AppLayer::SMB},
            {uint16_t{137},  AppLayer::SMB},
            {uint16_t{138},  AppLayer::SMB},
            {uint16_t{139},  AppLayer::SMB},
            {uint16_t{21},   AppLayer::FTP},
            {uint16_t{22},   AppLayer::SSH},
            {uint16_t{25},   AppLayer::SMTP},
            {uint16_t{587},  AppLayer::SMTP},
            {uint16_t{123},  AppLayer::NTP},
            {uint16_t{67},   AppLayer::DHCP},
            {uint16_t{68},   AppLayer::DHCP},
        };
    }

    // ============================================================================
    // LOAD NPCAP DLLs  — must load from System32\Npcap, not WinPcap
    // ============================================================================

    bool NetworkMonitor::LoadNpcapDlls() {
        wchar_t npcap_dir[512]{};
        UINT len = GetSystemDirectoryW(npcap_dir, 480);
        if (len == 0 || len > 480) {
            ConsoleLogger::LogError("GetSystemDirectory failed");
            return false;
        }
        wcsncat_s(npcap_dir, std::size(npcap_dir), L"\\Npcap", 6);

        if (SetDllDirectoryW(npcap_dir) == FALSE) {
            ConsoleLogger::LogError("SetDllDirectoryW(Npcap) failed");
            return false;
        }

        HMODULE h = LoadLibraryW(L"wpcap.dll");
        if (!h) {
            ConsoleLogger::LogError("Failed to load wpcap.dll from Npcap dir. "
                "Is Npcap installed?");
            SetDllDirectoryW(nullptr);
            return false;
        }

        SetDllDirectoryW(nullptr); // restore
        ConsoleLogger::LogInfo("Npcap DLLs loaded from System32\\Npcap");
        return true;
    }

    // ============================================================================
    // ENUMERATE ADAPTERS
    // ============================================================================

    void NetworkMonitor::EnumerateAdapters() {
        pcap_if_t* alldevs = nullptr;
        char errbuf[PCAP_ERRBUF_SIZE]{};

        if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
            ConsoleLogger::LogError(std::string("pcap_findalldevs: ") + errbuf);
            return;
        }

        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if (!d->name) continue;

            // Skip loopback unless explicitly requested
#ifndef TITAN_CAPTURE_LOOPBACK
            if (d->flags & PCAP_IF_LOOPBACK) continue;
#endif
            if ((d->flags & PCAP_IF_UP) == 0 ||
                (d->flags & PCAP_IF_RUNNING) == 0)
                continue;
            bool owns_local_address = false;
            for (pcap_addr_t* address = d->addresses;
                address != nullptr; address = address->next) {
                if (!address->addr) continue;
                char value[INET6_ADDRSTRLEN]{};
                if (address->addr->sa_family == AF_INET) {
                    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(
                        address->addr);
                    inet_ntop(AF_INET, &ipv4->sin_addr,
                        value, static_cast<DWORD>(std::size(value)));
                }
                else if (address->addr->sa_family == AF_INET6) {
                    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(
                        address->addr);
                    inet_ntop(AF_INET6, &ipv6->sin6_addr,
                        value, static_cast<DWORD>(std::size(value)));
                }
                if (value[0] != '\0' && IsLocalIp(value)) {
                    owns_local_address = true;
                    break;
                }
            }
            if (!owns_local_address) continue;
            AdapterCtx adapter;
            adapter.name = d->name;
            adapters_.push_back(std::move(adapter));
            ConsoleLogger::LogInfo(std::string("Adapter found: ") + d->name +
                (d->description ? std::string(" — ") + d->description : ""));
        }

        pcap_freealldevs(alldevs);
    }

    // ============================================================================
    // BUILD LOCAL IP SET  — used for direction detection (INBOUND vs OUTBOUND)
    // ============================================================================

    void NetworkMonitor::BuildLocalIpSet() {
        std::lock_guard<std::mutex> lock(local_ip_mutex_);
        local_ips_.clear();

        ULONG buf_size = 15000;
        std::vector<BYTE> buf(buf_size);
        DWORD result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &buf_size);
        if (result == ERROR_BUFFER_OVERFLOW) {
            buf.resize(buf_size);
            result = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                &buf_size);
        }
        if (result != NO_ERROR) return;

        auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        while (adapter) {
            for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                char ip[46]{};
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                }
                else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    auto* sa6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof(ip));
                }
                if (ip[0]) local_ips_.insert(ip);
            }
            adapter = adapter->Next;
        }
    }

    bool NetworkMonitor::IsLocalIp(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(local_ip_mutex_);
        return local_ips_.count(ip) > 0;
    }

    // ============================================================================
    // START
    // ============================================================================

    bool NetworkMonitor::Start() {
        if (running_.load()) return false;

        ConsoleLogger::LogInfo("Starting NetworkMonitor (Npcap deep-packet)...");

        if (!LoadNpcapDlls()) return false;

        WSADATA wsd{};
        // FIX C6031: check WSAStartup return value
        if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
            ConsoleLogger::LogError("WSAStartup failed");
            return false;
        }

        BuildLocalIpSet();
        EnumerateAdapters();

        if (adapters_.empty()) {
            ConsoleLogger::LogError("No suitable adapters found for capture");
            return false;
        }

        running_.store(true);

        // Start PID refresh thread
        pid_refresh_thread_ = std::thread([this] {
            while (running_.load()) {
                RefreshPidCache();
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(kPidRefreshMs));
            }
            });

        // Open pcap handle + start capture thread per adapter
        size_t active_handles = 0;
        for (auto& ctx : adapters_) {
            char errbuf[PCAP_ERRBUF_SIZE]{};
            ctx.handle = OpenConfiguredCapture(
                ctx.name.c_str(),
                65535,           // snaplen — full packet
                1,               // promiscuous mode
                100,             // read timeout ms
                errbuf);

            if (!ctx.handle) {
                ConsoleLogger::LogError(
                    std::string("pcap_open_live(") + ctx.name + "): " + errbuf);
                continue;
            }
            OpenRawDumper(ctx);

            ctx.thread = std::thread(
                &NetworkMonitor::CaptureThread, this, &ctx);
            ++active_handles;

            ConsoleLogger::LogInfo(
                std::string("Capture started on ") + ctx.name);
        }

        ConsoleLogger::LogInfo("NetworkMonitor running — capturing all protocols");
        if (active_handles == 0) {
            running_.store(false);
            if (pid_refresh_thread_.joinable())
                pid_refresh_thread_.join();
            ConsoleLogger::LogError("Npcap could not open any capture adapter");
            return false;
        }
        return true;
    }

    // ============================================================================
    // STOP
    // ============================================================================

    void NetworkMonitor::Stop() {
        if (!running_.load()) return;

        stop_requested_.store(true);
        running_.store(false);

        for (auto& ctx : adapters_) {
            if (ctx.handle) {
                pcap_breakloop(ctx.handle);
            }
        }
        for (auto& ctx : adapters_) {
            if (ctx.thread.joinable()) ctx.thread.join();
            if (ctx.dumper) {
                pcap_dump_flush(ctx.dumper);
                pcap_dump_close(ctx.dumper);
                ctx.dumper = nullptr;
            }
            if (ctx.handle) {
                pcap_stat stats{};
                if (pcap_stats(ctx.handle, &stats) == 0) {
                    capture_drops_.fetch_add(
                        static_cast<uint64_t>(stats.ps_drop),
                        std::memory_order_relaxed);
                    interface_drops_.fetch_add(
                        static_cast<uint64_t>(stats.ps_ifdrop),
                        std::memory_order_relaxed);
                }
                pcap_close(ctx.handle);
                ctx.handle = nullptr;
            }
        }
        if (pid_refresh_thread_.joinable())
            pid_refresh_thread_.join();

        WSACleanup();
        ConsoleLogger::LogInfo("NetworkMonitor stopped");
    }

    // ============================================================================
    // CAPTURE THREAD — one per adapter
    // ============================================================================

    void NetworkMonitor::CaptureThread(AdapterCtx* adapter) {
        if (!adapter || !adapter->handle) return;
        pcap_t* handle = adapter->handle;

        // Lambda adapter for pcap_loop callback
        struct CbCtx { NetworkMonitor* self; AdapterCtx* adapter; };
        CbCtx cb_ctx{ this, adapter };

        pcap_loop(handle, 0,
            [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
                auto* ctx = reinterpret_cast<CbCtx*>(user);
                ctx->self->HandlePacket(hdr,
                    reinterpret_cast<const uint8_t*>(pkt),
                    *ctx->adapter);
            },
            reinterpret_cast<u_char*>(&cb_ctx));
    }

    // ============================================================================
    // HANDLE PACKET
    // ============================================================================

    void NetworkMonitor::HandlePacket(const struct pcap_pkthdr* header,
        const uint8_t* data,
        AdapterCtx& adapter)
    {
        if (!header || !data) return;
        // FORU.TXT section 4.3/4.4: Monitoring OFF stops new collection
        // entirely -- discard before any parsing/enrichment/raw-capture,
        // same semantic as Process's OnProcessEvent gate.
        if (!monitoring_enabled_.load(std::memory_order_relaxed)) return;
        RotateRawDumperIfNeeded(adapter, header->caplen + 16);
        int64_t rawRecordOffset = -1;
        std::string rawSegment;
        if (adapter.dumper) {
            rawRecordOffset = pcap_dump_ftell64(adapter.dumper);
            rawSegment = adapter.raw_current_path.filename().string();
            pcap_dump(reinterpret_cast<u_char*>(adapter.dumper), header, data);
        }
        pkts_captured_.fetch_add(1, std::memory_order_relaxed);
        if (header->caplen < sizeof(EthHeader)) {
            structured_unparsed_packets_.fetch_add(
                1, std::memory_order_relaxed);
            return;
        }

        NetworkInfo info;
        info.captured_length = header->caplen;
        info.wire_length = header->len;
        if (rawRecordOffset >= 24 && !rawSegment.empty()) {
            info.raw_capture_mapped = true;
            info.raw_capture_segment = std::move(rawSegment);
            info.raw_record_offset = static_cast<uint64_t>(rawRecordOffset);
            info.raw_data_offset = info.raw_record_offset + 16;
        }
        info.capture_epoch_us =
            static_cast<uint64_t>(header->ts.tv_sec) * 1'000'000ULL +
            static_cast<uint64_t>(header->ts.tv_usec);
        info.adapter_name = adapter.name;
        if (!ParseEthernet(data, header->caplen, info)) {
            structured_unparsed_packets_.fetch_add(
                1, std::memory_order_relaxed);
            return;
        }

        // Resolve PID (ICMP has no ports; fall back to UDP slot)
        if (info.local_port != 0)
            info.pid = LookupPid(info.local_addr, info.local_port,
                info.transport_protocol);

        // Resolve short process name only (no hash, no path, no user context)
        if (info.pid != 0)
            ResolveProcessName(info.pid, info);

        // Update flow state
        const bool emit = UpdateFlowState(info);

        if (emit) {
            if (adapter.dumper && pcap_dump_flush(adapter.dumper) != 0)
                raw_capture_failures_.fetch_add(1, std::memory_order_relaxed);
            auto event = Event::CreateNetworkEvent(
                info, EventSource::NpcapLive);
            logger_.LogEvent(std::move(event));
            flows_forwarded_.fetch_add(1, std::memory_order_relaxed);
        }
        else {
            suppressed_packets_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ============================================================================
    // ETHERNET PARSER
    // ============================================================================

    bool NetworkMonitor::ParseEthernet(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(EthHeader)) return false;
        const auto* eth = reinterpret_cast<const EthHeader*>(data);
        uint16_t etype = ntohs(eth->ether_type);
        out.is_broadcast = std::all_of(std::begin(eth->dst),
            std::end(eth->dst), [](uint8_t value) {
                return value == 0xFF;
            });

        const uint8_t* next = data + sizeof(EthHeader);
        uint32_t       remain = len - sizeof(EthHeader);
        for (unsigned depth = 0; depth < 2 &&
            (etype == kEtherTypeVlan || etype == kEtherTypeQinQ); ++depth) {
            if (remain < 4) return false;
            const uint16_t tag = static_cast<uint16_t>(
                (static_cast<uint16_t>(next[0]) << 8) | next[1]);
            out.vlan_ids.push_back(static_cast<uint16_t>(tag & 0x0FFF));
            etype = static_cast<uint16_t>(
                (static_cast<uint16_t>(next[2]) << 8) | next[3]);
            next += 4;
            remain -= 4;
        }
        out.ether_type = etype;

        if (etype == kEtherTypeIPv4) return ParseIPv4(next, remain, out);
        if (etype == kEtherTypeIPv6) return ParseIPv6(next, remain, out);
        if (etype == kEtherTypeArp) return ParseArp(next, remain, out);
        return false; // ARP etc. — not of interest
    }

    bool NetworkMonitor::ParseArp(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (!data || len < 28) return false;
        const uint16_t hardware = static_cast<uint16_t>(
            (static_cast<uint16_t>(data[0]) << 8) | data[1]);
        const uint16_t protocol = static_cast<uint16_t>(
            (static_cast<uint16_t>(data[2]) << 8) | data[3]);
        if (hardware != 1 || protocol != kEtherTypeIPv4 ||
            data[4] != 6 || data[5] != 4)
            return false;
        char sender[INET_ADDRSTRLEN]{};
        char target[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, data + 14, sender, sizeof(sender));
        inet_ntop(AF_INET, data + 24, target, sizeof(target));
        out.packet_src_addr = sender;
        out.packet_dst_addr = target;
        const bool sender_local = IsLocalIp(sender);
        const bool target_local = IsLocalIp(target);
        if (sender_local && !target_local) {
            out.local_addr = sender;
            out.remote_addr = target;
            out.direction = NetworkDirection::OUTBOUND;
        }
        else if (target_local && !sender_local) {
            out.local_addr = target;
            out.remote_addr = sender;
            out.direction = NetworkDirection::INBOUND;
        }
        else {
            out.local_addr = sender;
            out.remote_addr = target;
            out.direction = NetworkDirection::UNKNOWN;
        }
        out.transport_protocol = 0;
        out.app_layer = AppLayer::ARP;
        out.payload_length = len;
        return true;
    }

    // ============================================================================
    // IPv4 PARSER
    // ============================================================================

    bool NetworkMonitor::ParseIPv4(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(Ipv4Header)) return false;
        const auto* ip = reinterpret_cast<const Ipv4Header*>(data);
        if ((ip->ver_ihl >> 4) != 4) return false;
        uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > len) return false;

        char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, ip->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, ip->dst_ip, dst, sizeof(dst));
        out.packet_src_addr = src;
        out.packet_dst_addr = dst;

        bool src_local = IsLocalIp(src);
        bool dst_local = IsLocalIp(dst);

        out.is_ipv6 = false;
        out.is_loopback = (std::string(src).rfind("127.", 0) == 0 ||
            std::string(dst).rfind("127.", 0) == 0);
        out.is_broadcast = out.is_broadcast || (
            ip->dst_ip[0] == 255 && ip->dst_ip[1] == 255 &&
            ip->dst_ip[2] == 255 && ip->dst_ip[3] == 255);

        // Direction: outbound if src is local, inbound if dst is local
        if (src_local && !dst_local) {
            out.local_addr = src;
            out.remote_addr = dst;
            out.direction = NetworkDirection::OUTBOUND;
        }
        else if (dst_local && !src_local) {
            out.local_addr = dst;
            out.remote_addr = src;
            out.direction = NetworkDirection::INBOUND;
        }
        else {
            out.local_addr = src;
            out.remote_addr = dst;
            out.direction = NetworkDirection::UNKNOWN;
        }

        const uint16_t declared_length = ntohs(ip->total_len);
        if (declared_length < ihl) return false;
        len = (std::min)(len, static_cast<uint32_t>(declared_length));
        const uint8_t* transport = data + ihl;
        uint32_t       t_len = len - ihl;

        const uint16_t fragment = ntohs(ip->flags_frag);
        out.fragment_offset = static_cast<uint16_t>(fragment & 0x1FFF);
        out.more_fragments = (fragment & 0x2000) != 0;
        out.fragmented = out.fragment_offset != 0 || out.more_fragments;
        out.transport_protocol = ip->protocol;
        if (out.fragment_offset != 0) {
            out.app_layer = AppLayer::IP_FRAGMENT;
            return true;
        }
        switch (ip->protocol) {
        case IPPROTO_TCP:
            out.is_tcp = true;
            return ParseTCP(transport, t_len, out, src_local);
        case IPPROTO_UDP:
            out.is_tcp = false;
            return ParseUDP(transport, t_len, out, src_local);
        case IPPROTO_ICMP:
            out.is_tcp = false;
            return ParseICMP(transport, t_len, out);
        default:
            return false;
        }
        return false;
    }

    // ============================================================================
    // IPv6 PARSER
    // ============================================================================

    bool NetworkMonitor::ParseIPv6(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(Ipv6Header)) return false;
        const auto* ip6 = reinterpret_cast<const Ipv6Header*>(data);
        if ((ntohl(ip6->ver_tc_flow) >> 28) != 6) return false;

        char src[INET6_ADDRSTRLEN]{}, dst[INET6_ADDRSTRLEN]{};
        inet_ntop(AF_INET6, ip6->src_ip, src, sizeof(src));
        inet_ntop(AF_INET6, ip6->dst_ip, dst, sizeof(dst));
        out.packet_src_addr = src;
        out.packet_dst_addr = dst;

        bool src_local = IsLocalIp(src);
        bool dst_local = IsLocalIp(dst);
        out.is_ipv6 = true;
        out.is_loopback = (std::string(src) == "::1" || std::string(dst) == "::1");

        if (src_local) {
            out.local_addr = src; out.remote_addr = dst;
            out.direction = NetworkDirection::OUTBOUND;
        }
        else if (dst_local && !src_local) {
            out.local_addr = dst; out.remote_addr = src;
            out.direction = NetworkDirection::INBOUND;
        }
        else {
            out.local_addr = src; out.remote_addr = dst;
            out.direction = NetworkDirection::UNKNOWN;
        }

        uint32_t offset = sizeof(Ipv6Header);
        const uint16_t declared_payload = ntohs(ip6->payload_len);
        if (declared_payload != 0) {
            const uint32_t declared_length =
                static_cast<uint32_t>(declared_payload) +
                static_cast<uint32_t>(sizeof(Ipv6Header));
            len = (std::min)(len, declared_length);
        }
        uint8_t next_header = ip6->next_header;
        for (unsigned depth = 0; depth < 8; ++depth) {
            if (next_header == 0 || next_header == 43 ||
                next_header == 60) {
                if (offset + 2 > len) return false;
                const uint32_t extension_length =
                    static_cast<uint32_t>(data[offset + 1] + 1) * 8;
                if (extension_length < 8 ||
                    offset + extension_length > len) return false;
                next_header = data[offset];
                offset += extension_length;
                continue;
            }
            if (next_header == 44) {
                if (offset + 8 > len) return false;
                const uint16_t fragment = static_cast<uint16_t>(
                    (static_cast<uint16_t>(data[offset + 2]) << 8) |
                    data[offset + 3]);
                out.fragmented = true;
                out.fragment_offset =
                    static_cast<uint16_t>((fragment >> 3) & 0x1FFF);
                out.more_fragments = (fragment & 0x1) != 0;
                next_header = data[offset];
                offset += 8;
                if (out.fragment_offset != 0) {
                    out.transport_protocol = next_header;
                    out.app_layer = AppLayer::IP_FRAGMENT;
                    return true;
                }
                continue;
            }
            if (next_header == 51) {
                if (offset + 2 > len) return false;
                const uint32_t extension_length =
                    static_cast<uint32_t>(data[offset + 1] + 2) * 4;
                if (extension_length < 8 ||
                    offset + extension_length > len) return false;
                next_header = data[offset];
                offset += extension_length;
                continue;
            }
            break;
        }
        out.transport_protocol = next_header;
        if (next_header == 50) {
            out.app_layer = AppLayer::IPSEC;
            return true;
        }
        if (offset > len) return false;
        const uint8_t* transport = data + offset;
        uint32_t       t_len = len - offset;

        switch (next_header) {
        case IPPROTO_TCP:
            out.is_tcp = true;
            return ParseTCP(transport, t_len, out, src_local);
        case IPPROTO_UDP:
            out.is_tcp = false;
            return ParseUDP(transport, t_len, out, src_local);
        case 58: // ICMPv6
            out.is_tcp = false;
            return ParseICMP(transport, t_len, out);
        default:
            return false;
        }
        return false;
    }

    // ============================================================================
    // TCP PARSER
    // ============================================================================

    bool NetworkMonitor::ParseTCP(const uint8_t* data, uint32_t len,
        NetworkInfo& out, bool is_src_local)
    {
        if (len < sizeof(TcpHeader)) return false;
        const auto* tcp = reinterpret_cast<const TcpHeader*>(data);

        uint16_t sp = ntohs(tcp->src_port);
        uint16_t dp = ntohs(tcp->dst_port);

        out.local_port = is_src_local ? sp : dp;
        out.remote_port = is_src_local ? dp : sp;

        // TCP state from flags
        uint8_t fl = tcp->flags;
        if ((fl & kTcpSyn) && !(fl & kTcpAck))  out.tcp_state = TcpState::SYN_SENT;
        else if ((fl & kTcpSyn) && (fl & kTcpAck))  out.tcp_state = TcpState::SYN_RECEIVED;
        else if ((fl & kTcpFin) || (fl & kTcpRst))   out.tcp_state = TcpState::CLOSED;
        else                                            out.tcp_state = TcpState::ESTABLISHED;

        uint32_t hdr_len = static_cast<uint32_t>((tcp->data_offset >> 4) * 4);
        if (hdr_len < sizeof(TcpHeader) || hdr_len > len) return false;

        const uint8_t* payload = data + hdr_len;
        uint32_t       payload_len = len - hdr_len;
        out.payload_length = payload_len;

        if (payload_len > 0) {
            // Port-based initial hint
            auto it = port_app_map_.find(out.remote_port);
            if (it == port_app_map_.end()) it = port_app_map_.find(out.local_port);
            if (it != port_app_map_.end()) {
                out.port_hint = it->second;
                out.app_layer = it->second;
            }

            // Payload inspection overrides port hint -- if it actually
            // identified something and that disagrees with what the port
            // implied, record that disagreement rather than silently
            // discarding it (see NetworkInfo::protocol_mismatch).
            IdentifyAppLayer(payload, payload_len, out);
            if (out.port_hint != AppLayer::UNKNOWN &&
                out.app_layer != AppLayer::UNKNOWN &&
                out.app_layer != out.port_hint) {
                out.protocol_mismatch = true;
            }
            if (out.local_port == 53 || out.remote_port == 53) {
                ParseDnsQuery(payload, payload_len, true, out);
                ParseDnsResponse(payload, payload_len, true, out);
            }
        }
        return true;
    }

    // ============================================================================
    // UDP PARSER
    // ============================================================================

    bool NetworkMonitor::ParseUDP(const uint8_t* data, uint32_t len,
        NetworkInfo& out, bool is_src_local)
    {
        if (len < sizeof(UdpHeader)) return false;
        const auto* udp = reinterpret_cast<const UdpHeader*>(data);
        const uint16_t datagram_length = ntohs(udp->length);
        const uint32_t effective_length =
            datagram_length == 0 && out.is_ipv6
            ? len : static_cast<uint32_t>(datagram_length);
        if (effective_length < sizeof(UdpHeader) ||
            effective_length > len)
            return false;

        uint16_t sp = ntohs(udp->src_port);
        uint16_t dp = ntohs(udp->dst_port);

        out.local_port = is_src_local ? sp : dp;
        out.remote_port = is_src_local ? dp : sp;

        auto it = port_app_map_.find(out.remote_port);
        if (it == port_app_map_.end()) it = port_app_map_.find(out.local_port);
        if (it != port_app_map_.end()) {
            out.port_hint = it->second;
            out.app_layer = it->second;
        }

        const uint8_t* payload = data + sizeof(UdpHeader);
        uint32_t payload_len =
            effective_length - static_cast<uint32_t>(sizeof(UdpHeader));
        out.payload_length = payload_len;
        if (payload_len > 0) {
            IdentifyAppLayer(payload, payload_len, out);
            if (out.port_hint != AppLayer::UNKNOWN &&
                out.app_layer != AppLayer::UNKNOWN &&
                out.app_layer != out.port_hint) {
                out.protocol_mismatch = true;
            }
            if (out.local_port == 53 || out.remote_port == 53) {
                ParseDnsQuery(payload, payload_len, false, out);
                ParseDnsResponse(payload, payload_len, false, out);
            }
        }
        return true;
    }

    // ============================================================================
    // ICMP PARSER
    // ============================================================================

    bool NetworkMonitor::ParseICMP(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        if (len < sizeof(IcmpHeader)) return false;
        const auto* icmp = reinterpret_cast<const IcmpHeader*>(data);
        out.app_layer = AppLayer::ICMP;
        out.payload_length =
            len > sizeof(IcmpHeader) ? len - sizeof(IcmpHeader) : 0;
        (void)icmp; // type/code fields removed from NetworkInfo
        return true;
    }

    // ============================================================================
    // APPLICATION LAYER IDENTIFICATION
    // ============================================================================

    void NetworkMonitor::IdentifyAppLayer(const uint8_t* payload, uint32_t len,
        NetworkInfo& out)
    {
        if (len == 0 || payload == nullptr) return;

        // TLS ClientHello: record type 0x16, version 0x03xx
        if (len >= 5 && payload[0] == 0x16 && payload[1] == 0x03) {
            out.app_layer = AppLayer::HTTPS_TLS;
            ParseTlsClientHello(payload, len, out);
            return;
        }

        // HTTP request line
        if (len >= 4) {
            auto starts = [&](const char* s) {
                size_t n = strlen(s);
                return len >= n &&
                    memcmp(payload, s, n) == 0;
                };
            if (starts("GET ") || starts("POST ") || starts("PUT ") ||
                starts("HEAD ") || starts("PATCH") || starts("DELETE ") ||
                starts("OPTIO") || starts("HTTP/"))
            {
                out.app_layer = AppLayer::HTTP;
                ParseHttpMessage(payload, len, out);
                return;
            }
        }

        // QUIC (v1 long header: first byte bit 7 set, bits 6-4 = 0x30..0x3F for Initial)
        if (len >= 5 && (payload[0] & 0xC0) == 0xC0) {
            uint32_t version = (static_cast<uint32_t>(payload[1]) << 24) |
                (static_cast<uint32_t>(payload[2]) << 16) |
                (static_cast<uint32_t>(payload[3]) << 8) |
                static_cast<uint32_t>(payload[4]);
            if (version == 0x00000001 || version == 0xFF000001) {
                out.app_layer = AppLayer::QUIC;
                return;
            }
        }

        // SSH banner
        if (len >= 4 && memcmp(payload, "SSH-", 4) == 0) {
            out.app_layer = AppLayer::SSH;
            return;
        }

        // SMTP greeting / HELO
        if (len >= 4 && (memcmp(payload, "220 ", 4) == 0 ||
            memcmp(payload, "EHLO", 4) == 0 ||
            memcmp(payload, "HELO", 4) == 0))
        {
            out.app_layer = AppLayer::SMTP;
            return;
        }

        // RDP: first byte 0x03, second 0x00 (TPKT header)
        if (len >= 4 && payload[0] == 0x03 && payload[1] == 0x00) {
            if (out.remote_port == 3389 || out.local_port == 3389) {
                out.app_layer = AppLayer::RDP;
                return;
            }
        }

        // SMB: NetBIOS Session Service 0x00 + SMB magic \xFFSMB or \xFESMB
        if (len >= 8 && payload[0] == 0x00) {
            if ((len >= 8 && memcmp(payload + 4, "\xFFSMB", 4) == 0) ||
                (len >= 8 && memcmp(payload + 4, "\xFESMB", 4) == 0))
            {
                out.app_layer = AppLayer::SMB;
                return;
            }
        }
    }

    void NetworkMonitor::ParseDnsQuery(const uint8_t* payload, uint32_t len,
        bool tcp, NetworkInfo& out)
    {
        if (protocol::DecodeDnsQuery(payload, len, tcp,
            out.dns_query, out.dns_query_type))
            out.app_layer = AppLayer::DNS;
    }

    void NetworkMonitor::ParseDnsResponse(const uint8_t* payload, uint32_t len,
        bool tcp, NetworkInfo& out)
    {
        if (protocol::DecodeDnsResponse(payload, len, tcp, out.dns_answers))
            out.app_layer = AppLayer::DNS;
    }

    void NetworkMonitor::ParseTlsClientHello(const uint8_t* data, uint32_t len,
        NetworkInfo& out)
    {
        protocol::DecodeTlsSni(data, len, out.tls_sni);
    }

    void NetworkMonitor::ParseHttpMessage(const uint8_t* payload, uint32_t len,
        NetworkInfo& out)
    {
        bool is_request = false;
        uint16_t status_code = 0;
        std::string method, target, reason, host;
        if (!protocol::DecodeHttpMessage(payload, len, is_request, method,
            target, status_code, reason, host))
            return;
        out.http_is_request = is_request;
        out.http_method = std::move(method);
        out.http_target = std::move(target);
        out.http_status_code = status_code;
        out.http_reason = std::move(reason);
        out.http_host = std::move(host);
    }

    // ============================================================================
    // FLOW STATE UPDATE
    // ============================================================================

    bool NetworkMonitor::UpdateFlowState(NetworkInfo& info)
    {
        FlowKey key{
            info.local_addr, info.remote_addr,
            info.local_port, info.remote_port,
            info.transport_protocol
        };

        std::lock_guard<std::mutex> lock(flow_mutex_);
        auto now = std::chrono::steady_clock::now();

        bool emit = false;
        auto it = flow_table_.find(key);
        if (it == flow_table_.end()) {
            ++flow_insertions_;
            if ((flow_insertions_ & 0x3FFULL) == 0) {
                const auto stale_before = now - std::chrono::minutes(5);
                for (auto candidate = flow_table_.begin();
                    candidate != flow_table_.end();) {
                    if (candidate->second.last_seen < stale_before)
                        candidate = flow_table_.erase(candidate);
                    else
                        ++candidate;
                }
            }
            if (flow_table_.size() >= kMaxFlows) {
                flow_table_.erase(flow_table_.begin());
            }
            FlowState state;
            state.first_seen = now;
            state.last_seen = now;
            state.last_emitted = now;
            state.direction = info.direction;
            state.tcp_state = info.tcp_state;
            state.pid = info.pid;
            state.packet_count = 1;
            state.last_emitted_packet_count = 1;
            info.packets_since_last_log = 1;
            if (info.direction == NetworkDirection::OUTBOUND)
                state.bytes_sent = info.payload_length;
            else if (info.direction == NetworkDirection::INBOUND)
                state.bytes_recv = info.payload_length;
            flow_table_[key] = state;
            emit = true;
        }
        else {
            FlowState& state = it->second;
            state.last_seen = now;
            state.packet_count++;
            state.tcp_state = info.tcp_state;
            if (info.direction == NetworkDirection::OUTBOUND)
                state.bytes_sent += info.payload_length;
            else if (info.direction == NetworkDirection::INBOUND)
                state.bytes_recv += info.payload_length;
            if (now - state.last_emitted >= std::chrono::seconds(30)) {
                info.packets_since_last_log = static_cast<uint32_t>(
                    state.packet_count - state.last_emitted_packet_count);
                state.last_emitted_packet_count = state.packet_count;
                state.last_emitted = now;
                emit = true;
            }
        }
        const auto current = flow_table_.find(key);
        if (current != flow_table_.end()) {
            info.bytes_sent = current->second.bytes_sent;
            info.bytes_recv = current->second.bytes_recv;
            info.packet_count = current->second.packet_count;
            info.flow_duration_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    current->second.last_seen -
                    current->second.first_seen).count());
        }
        return emit;
    }

    // ============================================================================
    // PID RESOLUTION  (IP Helper API)
    // ============================================================================

    void NetworkMonitor::RefreshPidCache() {
        std::unordered_map<SocketPidKey, DWORD, SocketPidKeyHash> new_cache;
        const auto remember_pid = [&new_cache](
            SocketPidKey key, DWORD pid) {
            const auto existing = new_cache.find(key);
            if (existing != new_cache.end()) {
                existing->second = pid;
            }
            else if (new_cache.size() < kMaxPidEntries) {
                new_cache.emplace(std::move(key), pid);
            }
        };

        // TCP v4
        {
            ULONG size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_TCPTABLE)))
                size = static_cast<ULONG>(sizeof(MIB_TCPTABLE));
            std::vector<BYTE> buf(size);
            if (GetExtendedTcpTable(buf.data(), &size, FALSE,
                AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                auto* tbl = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET_ADDRSTRLEN]{};
                    in_addr a{}; a.s_addr = tbl->table[i].dwLocalAddr;
                    inet_ntop(AF_INET, &a, ip, sizeof(ip));
                    SocketPidKey k;
                    k.local_ip = ip;
                    k.local_port = static_cast<uint16_t>(ntohs(static_cast<uint16_t>(tbl->table[i].dwLocalPort)));
                    k.proto = static_cast<uint8_t>(IPPROTO_TCP);
                    remember_pid(std::move(k), tbl->table[i].dwOwningPid);
                }
            }
        }

        // TCP v6
        {
            ULONG size = 0;
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_TCP6TABLE_OWNER_PID)))
                size = static_cast<ULONG>(sizeof(MIB_TCP6TABLE_OWNER_PID));
            std::vector<BYTE> buf(size);
            if (GetExtendedTcpTable(buf.data(), &size, FALSE,
                AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                auto* tbl = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, tbl->table[i].ucLocalAddr, ip, sizeof(ip));
                    SocketPidKey k;
                    k.local_ip = ip;
                    k.local_port = static_cast<uint16_t>(ntohs(static_cast<uint16_t>(tbl->table[i].dwLocalPort)));
                    k.proto = static_cast<uint8_t>(IPPROTO_TCP);
                    remember_pid(std::move(k), tbl->table[i].dwOwningPid);
                }
            }
        }

        // UDP v4
        {
            ULONG size = 0;
            GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_UDPTABLE)))
                size = static_cast<ULONG>(sizeof(MIB_UDPTABLE));
            std::vector<BYTE> buf(size);
            if (GetExtendedUdpTable(buf.data(), &size, FALSE,
                AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            {
                auto* tbl = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET_ADDRSTRLEN]{};
                    in_addr a{}; a.s_addr = tbl->table[i].dwLocalAddr;
                    inet_ntop(AF_INET, &a, ip, sizeof(ip));
                    SocketPidKey k;
                    k.local_ip = ip;
                    k.local_port = static_cast<uint16_t>(ntohs(static_cast<uint16_t>(tbl->table[i].dwLocalPort)));
                    k.proto = static_cast<uint8_t>(IPPROTO_UDP);
                    remember_pid(std::move(k), tbl->table[i].dwOwningPid);
                }
            }
        }

        // UDP v6
        {
            ULONG size = 0;
            GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6,
                UDP_TABLE_OWNER_PID, 0);
            if (size < static_cast<ULONG>(sizeof(MIB_UDP6TABLE_OWNER_PID)))
                size = static_cast<ULONG>(sizeof(MIB_UDP6TABLE_OWNER_PID));
            std::vector<BYTE> buf(size);
            if (GetExtendedUdpTable(buf.data(), &size, FALSE,
                AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            {
                auto* tbl =
                    reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    char ip[INET6_ADDRSTRLEN]{};
                    inet_ntop(AF_INET6, tbl->table[i].ucLocalAddr,
                        ip, sizeof(ip));
                    SocketPidKey key;
                    key.local_ip = ip;
                    key.local_port = static_cast<uint16_t>(ntohs(
                        static_cast<uint16_t>(
                            tbl->table[i].dwLocalPort)));
                    key.proto = static_cast<uint8_t>(IPPROTO_UDP);
                    remember_pid(
                        std::move(key), tbl->table[i].dwOwningPid);
                }
            }
        }

        std::lock_guard<std::mutex> lock(pid_mutex_);
        pid_cache_ = std::move(new_cache);
    }

    DWORD NetworkMonitor::LookupPid(const std::string& local_ip,
        uint16_t local_port, uint8_t proto) const
    {
        std::lock_guard<std::mutex> lock(pid_mutex_);
        SocketPidKey key;
        key.local_ip = local_ip;
        key.local_port = local_port;
        key.proto = proto;
        auto it = pid_cache_.find(key);
        if (it != pid_cache_.end()) return it->second;
        key.local_ip = local_ip.find(':') == std::string::npos
            ? "0.0.0.0" : "::";
        it = pid_cache_.find(key);
        if (it != pid_cache_.end()) return it->second;
        return 0;
    }

    // ============================================================================
    // RESOLVE PROCESS NAME
    // Lightweight replacement for EnrichProcessFields.
    // Sets process_name to the short executable filename only.
    // No hash, no path, no user context -- this is a network endpoint.
    // ============================================================================

    void NetworkMonitor::ResolveProcessName(DWORD pid, NetworkInfo& out) {
        if (pid == 0) return;

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return;

        std::vector<wchar_t> buf(32768, L'\0');
        DWORD sz = static_cast<DWORD>(buf.size());
        if (QueryFullProcessImageNameW(h, 0, buf.data(), &sz) && sz > 0) {
            std::wstring full(buf.data(), sz);
            auto pos = full.find_last_of(L"\\/");
            out.process_name = (pos != std::wstring::npos)
                ? full.substr(pos + 1)
                : full;
        }

        CloseHandle(h);
    }


} // namespace titan
