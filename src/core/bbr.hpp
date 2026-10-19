#pragma once

#include <cstdint>

namespace genesis {

enum class BbrMode : uint8_t { Startup = 0, Drain = 1, ProbeBw = 2, ProbeRtt = 3 };
enum class ProbePhase : uint8_t { Cruise = 0, Refill = 1, Up = 2, Down = 3 };

/* User-space BBRv3-style controller. It is not a line-by-line port of the
 * kernel module: pacing and cwnd are computed in this process from delivery-rate
 * and min-RTT samples, which is what the assessment asks for (do not flip the
 * kernel BBR sysctl). Gains follow the published startup (2.77), drain, ProbeBW
 * cruise/refill/up/down cycle, and periodic ProbeRTT. */
class Bbr {
public:
    void reset(uint32_t mss, int profile);
    void on_sent(uint64_t seq, uint32_t bytes, uint64_t now_us);
    void on_ack(uint64_t seq, uint32_t bytes, uint64_t now_us);
    void on_loss(uint32_t bytes, uint64_t now_us);
    void tick(uint64_t now_us);

    uint64_t pacing_bps() const { return pacing_bps_; }
    uint64_t cwnd_bytes() const { return cwnd_; }
    uint64_t min_rtt_us() const { return min_rtt_ == ~0ull ? 0 : min_rtt_; }
    uint64_t max_bw_bps() const { return max_bw_; }
    uint64_t inflight() const { return inflight_; }
    BbrMode mode() const { return mode_; }
    ProbePhase phase() const { return phase_; }
    int effective_profile() const { return effective_; }
    double pacing_gain() const { return gain_; }

private:
    struct Rec {
        uint64_t seq = 0;
        uint64_t sent_us = 0;
        uint64_t delivered = 0;
        uint64_t delivered_us = 0;
        uint32_t bytes = 0;
        bool valid = false;
    };

    void note_bw(uint64_t bw);
    void close_round(uint64_t now_us);
    void enter(BbrMode m, uint64_t now_us);
    void refresh_gains();
    void retarget();

    static constexpr int kRecs = 2048;
    Rec recs_[kRecs];
    uint32_t mss_ = 1200;
    int requested_ = 0;
    int effective_ = 1;
    BbrMode mode_ = BbrMode::Startup;
    BbrMode saved_mode_ = BbrMode::ProbeBw;
    ProbePhase phase_ = ProbePhase::Cruise;
    double gain_ = 2.77;
    uint64_t max_bw_ = 0;
    uint64_t min_rtt_ = ~0ull;
    uint64_t min_rtt_stamp_ = 0;
    uint64_t delivered_ = 0;
    uint64_t delivered_us_ = 0;
    uint64_t inflight_ = 0;
    uint64_t cwnd_ = 0;
    uint64_t pacing_bps_ = 0;
    uint64_t initial_bps_ = 0;
    uint64_t round_end_ = 0;
    bool round_open_ = false;
    int rounds_ = 0;
    int stagnant_ = 0;
    int phase_rounds_ = 0;
    uint64_t round_bw_ = 0;
    uint64_t bw_ring_[10]{};
    int bw_n_ = 0;
    uint64_t bw_before_plateau_ = 0;
    int cell_votes_ = 0;
    int gbe_votes_ = 0;
    uint64_t lost_bytes_ = 0;
    uint64_t probe_rtt_until_ = 0;
    bool have_bw_ = false;
};

}  // namespace genesis
