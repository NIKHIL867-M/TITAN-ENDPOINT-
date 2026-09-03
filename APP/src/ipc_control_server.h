#pragma once

// ============================================================================
// ipc_control_server.h — FORU.TXT section 4 (+ section 12's revisioned
// watchlist control), extended to the Application endpoint. Same
// authenticated named-pipe pattern as
// PROCESS ENDPOINT\titan_fixed\ipc_control_server.h -- see that file's
// header comment for the full session/revision/audit rationale, not
// repeated here. Global namespace, matching this program's own convention
// (no `namespace titan` wrapper anywhere in APP\src).
//
// Extra command beyond the standard six: SetWatchlist. FORU.TXT section 12:
// "Replace watchlist polling with authenticated revisioned IPC. Native
// acknowledgement must include the endpoint session ID and exact accepted
// revision so an old acknowledgement cannot satisfy a new request." Applies
// the requested application list via AppLogMonitor::ApplyWatchlistRevisioned
// and returns {"session_id":..., "accepted_revision":...} in the same
// response. The legacy file-poll path (config\watchlist.txt +
// watchlist_state.json) still runs alongside this -- both funnel through the
// same ApplyWatchlistRevisioned/revision counter, so they can never disagree
// about the current state, and the GUI's own migration from file-polling to
// calling this command directly is separate follow-up work, not done here.
// ============================================================================

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <functional>

class AppLogMonitor;

class IpcControlServer {
public:
    IpcControlServer(AppLogMonitor& monitor, std::function<void()> shutdownCallback);
    ~IpcControlServer();

    IpcControlServer(const IpcControlServer&) = delete;
    IpcControlServer& operator=(const IpcControlServer&) = delete;

    bool Start();
    void Stop();

    static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\TitanEndpoint_Application_Control";

private:
    void ServerLoop();
    void HandleOneConnection(void* pipeHandle);
    std::string Dispatch(const std::string& requestJson, void* pipeHandle);
    static std::string CaptureCallerIdentity(void* pipeHandle);

    AppLogMonitor& monitor_;
    std::function<void()> shutdown_callback_;

    std::atomic<bool> running_{ false };
    std::atomic<uint64_t> revision_{ 0 };
    std::thread server_thread_;
};
