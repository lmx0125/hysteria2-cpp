
/*
 * ngtcp2_cc_brutal: fixed-rate, loss-insensitive sender (Hysteria Brutal).
 * See ngtcp2_bbr.h.  Added by the ngtcp2_hy2_brutal_patch.
 *
 * Two halves, and both are required for the upstream behaviour:
 *
 *   1. the window, cwnd = rate * srtt * 2 / ack_rate (brutal.go
 *      GetCongestionWindow), which only decides how much may be in flight;
 *   2. the pacing rate, which decides *when* the bytes leave.  Without (2)
 *      the only limit is (1), so the sender dumps a whole window per RTT,
 *      the queue it builds inflates srtt, and the inflated srtt inflates the
 *      window again - the positive feedback that collapses a link whose real
 *      capacity is below the declared rate.  brutal.go pairs the two
 *      (NewPacer with bandwidth = bps / ackRate).
 */

/* brutal.go: ackRate is only moved once enough packets back it up. */
static void ngtcp2_cc_brutal_update_ack_rate(ngtcp2_cc_brutal *brutal,
                                             int64_t now_sec) {
  int64_t min_ts;
  uint64_t ack_count = 0, loss_count = 0;
  size_t i;
  double rate;

  if (brutal->loss_compensation_disabled || brutal->rate == 0) {
    brutal->ack_rate = 1.0;
    return;
  }

  min_ts = now_sec - NGTCP2_BRUTAL_PKT_INFO_SLOT_COUNT;
  for (i = 0; i < NGTCP2_BRUTAL_PKT_INFO_SLOT_COUNT; ++i) {
    if (brutal->pkt_info[i].timestamp < min_ts) {
      continue;
    }
    ack_count += brutal->pkt_info[i].ack_count;
    loss_count += brutal->pkt_info[i].loss_count;
  }

  if (ack_count + loss_count < NGTCP2_BRUTAL_MIN_SAMPLE_COUNT) {
    brutal->ack_rate = 1.0;
    return;
  }

  rate = (double)ack_count / (double)(ack_count + loss_count);
  if (rate < NGTCP2_BRUTAL_MIN_ACK_RATE) {
    rate = NGTCP2_BRUTAL_MIN_ACK_RATE;
  }
  brutal->ack_rate = rate;
}

/* Buckets this event's acked/lost packet counts into the second it happened
   in, exactly like brutal.go's OnCongestionEventEx slot handling. */
static void ngtcp2_cc_brutal_note(ngtcp2_cc_brutal *brutal, ngtcp2_tstamp ts,
                                  uint64_t acks, uint64_t losses) {
  int64_t now_sec = (int64_t)(ts / NGTCP2_SECONDS);
  size_t slot = (size_t)(now_sec % NGTCP2_BRUTAL_PKT_INFO_SLOT_COUNT);
  ngtcp2_cc_brutal_pkt_info *info = &brutal->pkt_info[slot];

  if (info->timestamp == now_sec) {
    info->ack_count += acks;
    info->loss_count += losses;
  } else {
    /* uninitialized slot or too old, reset */
    info->timestamp = now_sec;
    info->ack_count = acks;
    info->loss_count = losses;
  }
}

/* The rate the pacer runs at: the declared rate compensated for loss, i.e.
   the same `bps / ackRate` brutal.go hands to NewPacer. */
static uint64_t ngtcp2_cc_brutal_effective_rate(
  const ngtcp2_cc_brutal *brutal) {
  double r = (double)brutal->rate / brutal->ack_rate;
  if (r < 1.0) {
    r = 1.0;
  }
  return (uint64_t)r;
}

static void ngtcp2_cc_brutal_update_cwnd(ngtcp2_cc_brutal *brutal,
                                         ngtcp2_conn_stat *cstat) {
  uint64_t min_cwnd = 64 * 1024; /* hy2: floor the window: rate*srtt is only a few packets at low RTT (loopback/LAN) and ACK-jitter then throttles the flow; 64 KiB keeps the ACK clock fed and is far below the real-path rate*RTT window. */
  uint64_t target;

  if (brutal->rate == 0 || cstat->smoothed_rtt == 0) {
    return;
  }

  /* brutal.go: cwnd = bps * srtt * congestionWindowMultiplier / ackRate.
     The window is a ceiling for the pacer, not the rate control itself. */
  target = (uint64_t)((double)brutal->rate * (double)cstat->smoothed_rtt *
                      NGTCP2_BRUTAL_CWND_MULTIPLIER /
                      (1000000000.0 * brutal->ack_rate));
  if (target < min_cwnd) {
    target = min_cwnd;
  }
  cstat->cwnd = target;
}

/* Programs the connection pacer for the declared rate.  This is what turns
   "a window that happens to be sized like a BDP" into "a sender that emits at
   the declared rate": conn_write_pkt waits `pktlen * pacing_interval_m >> 10`
   ns after a burst, and ngtcp2_conn_get_expiry() reports that deadline, so the
   IO loop sleeps exactly until the next burst is due. */
static void ngtcp2_cc_brutal_update_pacing(ngtcp2_cc_brutal *brutal,
                                           ngtcp2_conn_stat *cstat) {
  uint64_t rate;
  uint64_t interval_m;
  size_t send_quantum;

  if (brutal->rate == 0) {
    /* Unarmed: leave whatever the previously active controller installed. */
    return;
  }

  rate = ngtcp2_cc_brutal_effective_rate(brutal);

  /* pacing_interval_m is nanoseconds-per-byte scaled by 1024. */
  interval_m = (uint64_t)((1000000000.0 / (double)rate) * 1024.0);
  if (interval_m == 0) {
    interval_m = 1;
  }
  cstat->pacing_interval_m = interval_m;

  /* Hysteria caps a pacer burst at max(4ms x bw, 10 x MTU) (pacer.go
     maxBurstSize).  Matching that here keeps the burst far below the
     bottleneck queue while making the period long enough that the wake-up
     timer's granularity stays a small fraction of it - ngtcp2's own
     controllers instead use min(64 KiB, 1 ms of data), and a ~1 ms period is
     paced badly by a ~1 ms Windows timer. */
  send_quantum = (size_t)(rate / 250); /* 4 ms of data at the current rate */
  if (send_quantum < 10 * cstat->max_tx_udp_payload_size) {
    send_quantum = 10 * cstat->max_tx_udp_payload_size;
  }
  cstat->send_quantum = send_quantum;
}

static void ngtcp2_cc_brutal_refresh(ngtcp2_cc_brutal *brutal,
                                     ngtcp2_conn_stat *cstat,
                                     ngtcp2_tstamp ts) {
  ngtcp2_cc_brutal_update_ack_rate(brutal, (int64_t)(ts / NGTCP2_SECONDS));
  ngtcp2_cc_brutal_update_cwnd(brutal, cstat);
  ngtcp2_cc_brutal_update_pacing(brutal, cstat);
}

static void ngtcp2_cc_brutal_on_pkt_acked(ngtcp2_cc *cc,
                                          ngtcp2_conn_stat *cstat,
                                          const ngtcp2_cc_pkt *pkt,
                                          ngtcp2_tstamp ts) {
  ngtcp2_cc_brutal *brutal = ngtcp2_struct_of(cc, ngtcp2_cc_brutal, cc);

  if (brutal->rate == 0) {
    /* Unarmed (handshake): plain ACK-clocked growth. */
    cstat->cwnd += pkt->pktlen;
    return;
  }

  ngtcp2_cc_brutal_note(brutal, ts, 1, 0);
  ngtcp2_cc_brutal_refresh(brutal, cstat, ts);
}

static void ngtcp2_cc_brutal_congestion_event(ngtcp2_cc *cc,
                                              ngtcp2_conn_stat *cstat,
                                              ngtcp2_tstamp sent_ts,
                                              const ngtcp2_cc_ack *ack,
                                              ngtcp2_tstamp ts) {
  ngtcp2_cc_brutal *brutal = ngtcp2_struct_of(cc, ngtcp2_cc_brutal, cc);
  uint64_t lost_pkts;

  (void)sent_ts;

  /* Loss never shrinks the window (see ngtcp2_cc_brutal_update_cwnd); it only
     feeds the ack-rate loss compensation. */
  if (brutal->rate == 0 || ack->bytes_lost == 0) {
    return;
  }

  /* ngtcp2 reports lost *bytes*; brutal.go counts lost *packets*. */
  lost_pkts = ack->bytes_lost / cstat->max_tx_udp_payload_size;
  if (lost_pkts == 0) {
    lost_pkts = 1;
  }

  ngtcp2_cc_brutal_note(brutal, ts, 0, lost_pkts);
  ngtcp2_cc_brutal_refresh(brutal, cstat, ts);
}

void ngtcp2_cc_brutal_init(ngtcp2_cc_brutal *brutal, ngtcp2_log *log,
                           ngtcp2_conn_stat *cstat) {
  *brutal = (ngtcp2_cc_brutal){
    .cc =
      {
        .log = log,
        .on_pkt_acked = ngtcp2_cc_brutal_on_pkt_acked,
        .congestion_event = ngtcp2_cc_brutal_congestion_event,
      },
    .rate = 0,
    .ack_rate = 1.0,
    .loss_compensation_disabled = 0,
  };

  cstat->cwnd = ngtcp2_cc_compute_initcwnd(cstat->max_tx_udp_payload_size);
}

void ngtcp2_cc_brutal_set_rate(ngtcp2_cc_brutal *brutal,
                               ngtcp2_conn_stat *cstat, uint64_t rate) {
  brutal->rate = rate;
  if (rate == 0) {
    brutal->ack_rate = 1.0;
    return;
  }
  ngtcp2_cc_brutal_update_cwnd(brutal, cstat);
  ngtcp2_cc_brutal_update_pacing(brutal, cstat);
}

void ngtcp2_cc_brutal_set_loss_compensation(ngtcp2_cc_brutal *brutal,
                                            ngtcp2_conn_stat *cstat,
                                            int disabled) {
  brutal->loss_compensation_disabled = disabled;
  if (disabled) {
    brutal->ack_rate = 1.0;
  }
  if (brutal->rate != 0) {
    ngtcp2_cc_brutal_update_cwnd(brutal, cstat);
    ngtcp2_cc_brutal_update_pacing(brutal, cstat);
  }
}
