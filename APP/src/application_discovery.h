#pragma once

#include "titan_pch.h"

struct DiscoveredApplication {
    std::string executable;
    std::string display_name;
    std::string publisher;
    std::string signature_status;
    std::wstring path;
    std::vector<DWORD> pids;
    bool installed = false;

    bool IsRunning() const { return !pids.empty(); }
};

class ApplicationDiscovery {
public:
    static std::vector<DiscoveredApplication> Discover(
        const std::string& filter = {});
};
