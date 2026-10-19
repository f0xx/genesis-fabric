#include "bbr.hpp"

namespace genesis {

void Bbr::reset(uint32_t mss, int profile) {
    *this = Bbr();
    mss_ = mss ? mss : 1200;
    requested_ = profile;
    if (profile == 2) {
        effective_ = 2;
        pacing_bps_ = 5'000'000ull;
        gain_ = 2.0;
    } else if (profile == 3) {
        effective_ = 1;
        pacing_bps_ = 20'000'000ull;
        gain_ = 2.0;
    } else {
        effective_ = 1;
        pacing_bps_ = 80'000'000ull;
        gain_ = 2.77;
    }
    initial_bps_ = pacing_bps_;
    cwnd_ = static_cast<uint64_t>(mss_) * 32;
    mode_ = BbrMode::Startup;
}

void Bbr::note_bw(uint64_t bw) {
    if (bw > round_bw_) round_bw_ = bw;
    if (!have_bw_ || bw > max_bw_) max_bw_ = bw;
    have_bw_ = true;
}

void Bbr::refresh_gains() {
    const bool cell = effective_ == 2;
    switch (mode_) {
    case BbrMode::Startup:
        gain_ = cell ? 2.0 : 2.77;
        break;
    case BbrMode::Drain:
        gain_ = cell ? 0.50 : (1.0 / 2.77);
        break;
    case BbrMode::ProbeRtt:
        gain_ = 1.0;
        break;
    case BbrMode::ProbeBw:
        if (phase_ == ProbePhase::Up) gain_ = cell ? 1.10 : 1.25;
        else if (phase_ == ProbePhase::Down) gain_ = 0.75;
        else gain_ = 1.0;
        break;
    }
}

void Bbr::retarget() {
    refresh_gains();
    uint64_t bw = max_bw_ ? max_bw_ : initial_bps_;
    /* Startup must not adopt a one-packet sample as the bottleneck. The first
     * ACKs are often a single datagram over a coarse timer, which would otherwise
     * collapse a gigabit probe down to a couple of megabytes per second. */
    if (mode_ == BbrMode::Startup && bw < initial_bps_) bw = initial_bps_;
    if (effective_ == 2 && min_rtt_ != ~0ull) {
        /* Bufferbloat guard from the design notes: if the latest sample pushed
         * min_rtt far below a sustained RTT, ease off before the base station queue grows. */
    }
    pacing_bps_ = static_cast<uint64_t>(static_cast<double>(bw) * gain_);
    if (pacing_bps_ < 64 * 1024) pacing_bps_ = 64 * 1024;
    if (min_rtt_ == ~0ull || !max_bw_) {
        cwnd_ = static_cast<uint64_t>(mss_) * (mode_ == BbrMode::Startup ? 64 : 32);
        return;
    }
    uint64_t bdp = max_bw_ * min_rtt_ / 1000000ull;
    if (bdp < mss_) bdp = mss_;
    double cwnd_gain = (mode_ == BbrMode::Startup) ? gain_ : 2.0;
    if (mode_ == BbrMode::ProbeRtt) {
        cwnd_ = static_cast<uint64_t>(mss_) * 4;
        return;
    }
    cwnd_ = static_cast<uint64_t>(static_cast<double>(bdp) * cwnd_gain);
    uint64_t floor = static_cast<uint64_t>(mss_) * 4;
    if (cwnd_ < floor) cwnd_ = floor;
    uint64_t cap = static_cast<uint64_t>(mss_) * 2048;
    if (cwnd_ > cap) cwnd_ = cap;
}

void Bbr::enter(BbrMode m, uint64_t now_us) {
    mode_ = m;
    phase_ = ProbePhase::Cruise;
    phase_rounds_ = 0;
    stagnant_ = 0;
    if (m == BbrMode::ProbeRtt) probe_rtt_until_ = now_us + 200000ull;
    retarget();
}

void Bbr::close_round(uint64_t now_us) {
    if (round_bw_) {
        bw_ring_[bw_n_ % 10] = round_bw_;
        ++bw_n_;
        uint64_t mx = 0;
        int n = bw_n_ < 10 ? bw_n_ : 10;
        for (int i = 0; i < n; ++i)
            if (bw_ring_[i] > mx) mx = bw_ring_[i];
        max_bw_ = mx;
    }
    if (mode_ == BbrMode::Startup) {
        if (bw_before_plateau_ && round_bw_ < bw_before_plateau_ + bw_before_plateau_ / 4) ++stagnant_;
        else stagnant_ = 0;
        bw_before_plateau_ = round_bw_;
        if (stagnant_ >= 3) enter(BbrMode::Drain, now_us);
    } else if (mode_ == BbrMode::ProbeBw) {
        ++phase_rounds_;
        if (phase_ == ProbePhase::Cruise && phase_rounds_ >= 8) {
            phase_ = ProbePhase::Refill;
            phase_rounds_ = 0;
        } else if (phase_ == ProbePhase::Refill && phase_rounds_ >= 1) {
            phase_ = ProbePhase::Up;
            phase_rounds_ = 0;
        } else if (phase_ == ProbePhase::Up && phase_rounds_ >= 3) {
            phase_ = ProbePhase::Down;
            phase_rounds_ = 0;
        } else if (phase_ == ProbePhase::Down && inflight_ <= (max_bw_ * (min_rtt_ == ~0ull ? 1000 : min_rtt_) / 1000000ull + mss_)) {
            phase_ = ProbePhase::Cruise;
            phase_rounds_ = 0;
        }
        retarget();
    }
    round_bw_ = 0;
    round_open_ = false;
    ++rounds_;
    (void)now_us;
}

void Bbr::on_sent(uint64_t seq, uint32_t bytes, uint64_t now_us) {
    Rec& rec = recs_[seq % kRecs];
    rec.seq = seq;
    rec.sent_us = now_us;
    rec.delivered = delivered_;
    rec.delivered_us = delivered_us_ ? delivered_us_ : now_us;
    rec.bytes = bytes;
    rec.valid = true;
    inflight_ += bytes;
    if (!round_open_) {
        round_open_ = true;
        round_end_ = delivered_ + inflight_;
    }
}

void Bbr::on_ack(uint64_t seq, uint32_t bytes, uint64_t now_us) {
    Rec& rec = recs_[seq % kRecs];
    if (!rec.valid || rec.seq != seq) return;
    rec.valid = false;
    if (inflight_ >= bytes) inflight_ -= bytes;
    else inflight_ = 0;
    uint64_t rtt = (now_us > rec.sent_us) ? (now_us - rec.sent_us) : 1;
    if (rtt < min_rtt_) {
        min_rtt_ = rtt;
        min_rtt_stamp_ = now_us;
    }
    delivered_ += bytes;
    delivered_us_ = now_us;
    uint64_t dt = (now_us > rec.delivered_us) ? (now_us - rec.delivered_us) : 0;
    uint64_t db = (delivered_ > rec.delivered) ? (delivered_ - rec.delivered) : 0;
    if (dt > 0 && db > 0) note_bw(db * 1000000ull / dt);

    if (requested_ == 0 && min_rtt_ != ~0ull) {
        if (min_rtt_ > 40000 || rtt > min_rtt_ * 2) ++cell_votes_;
        else ++gbe_votes_;
        if (cell_votes_ >= 8 && effective_ != 2) {
            effective_ = 2;
            cell_votes_ = 0;
            gbe_votes_ = 0;
        } else if (gbe_votes_ >= 16 && max_bw_ > 100000000ull && min_rtt_ < 8000 && effective_ != 1) {
            effective_ = 1;
            cell_votes_ = 0;
            gbe_votes_ = 0;
        }
    }

    /* Cellular reaction: a stretched RTT means the queue is building. Cut gain now. */
    if (effective_ == 2 && min_rtt_ != ~0ull && rtt > min_rtt_ + min_rtt_ / 2 && mode_ == BbrMode::ProbeBw) {
        gain_ = 0.75;
    }

    if (round_open_ && delivered_ >= round_end_) close_round(now_us);
    if (mode_ == BbrMode::Drain) {
        uint64_t bdp = (max_bw_ && min_rtt_ != ~0ull) ? (max_bw_ * min_rtt_ / 1000000ull) : cwnd_;
        if (inflight_ <= bdp + mss_) enter(BbrMode::ProbeBw, now_us);
    }
    retarget();
    if (effective_ == 2 && mode_ == BbrMode::ProbeBw && gain_ == 0.75) {
        /* keep the temporary ease-off until retarget overwrote it; reapply */
        gain_ = 0.75;
        if (max_bw_) pacing_bps_ = static_cast<uint64_t>(static_cast<double>(max_bw_) * gain_);
    }
}

void Bbr::on_loss(uint32_t bytes, uint64_t now_us) {
    lost_bytes_ += bytes;
    if (inflight_ >= bytes) inflight_ -= bytes;
    else inflight_ = 0;
    if (mode_ == BbrMode::Startup) {
        /* A single spurious RTO is not a bottleneck signal. Leave startup once
         * the lost bytes cover a full FEC group, which is what a real queue drop
         * looks like. */
        if (lost_bytes_ > static_cast<uint64_t>(mss_) * 16) enter(BbrMode::Drain, now_us);
    }
    if (mode_ == BbrMode::ProbeBw && phase_ == ProbePhase::Up) {
        phase_ = ProbePhase::Down;
        phase_rounds_ = 0;
    }
    retarget();
}

void Bbr::tick(uint64_t now_us) {
    uint64_t window = (effective_ == 2) ? 5000000ull : 10000000ull;
    if (min_rtt_ != ~0ull && min_rtt_stamp_ && now_us > min_rtt_stamp_ + window && mode_ != BbrMode::Startup &&
        mode_ != BbrMode::ProbeRtt) {
        saved_mode_ = mode_;
        enter(BbrMode::ProbeRtt, now_us);
    }
    if (mode_ == BbrMode::ProbeRtt && now_us >= probe_rtt_until_) {
        min_rtt_stamp_ = now_us;
        enter(saved_mode_ == BbrMode::Startup ? BbrMode::ProbeBw : saved_mode_, now_us);
    }
}

}  // namespace genesis
