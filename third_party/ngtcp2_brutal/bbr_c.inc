
/*
 * ngtcp2_cc_brutal: fixed-rate, loss-insensitive sender (Hysteria Brutal).
 * See ngtcp2_bbr.h.  Added by the ngtcp2_hy2_brutal_patch.
 */
static void ngtcp2_cc_brutal_update_cwnd(ngtcp2_cc_brutal *brutal,
                                         ngtcp2_conn_stat *cstat) {
  uint64_t min_cwnd = 2 * cstat->max_tx_udp_payload_size;
  uint64_t target;

  if (brutal->rate == 0 || cstat->smoothed_rtt == 0) {
    return;
  }

  /* ACK-clocked fixed rate: a window of rate * srtt emits one window per
     RTT, i.e. exactly the declared rate.  Loss is deliberately not
     consulted - the rate is a contract, not an estimate. */
  target = (uint64_t)((double)brutal->rate * (double)cstat->smoothed_rtt /
                      1000000000.0);
  if (target < min_cwnd) {
    target = min_cwnd;
  }
  cstat->cwnd = target;
}

static void ngtcp2_cc_brutal_on_pkt_acked(ngtcp2_cc *cc,
                                          ngtcp2_conn_stat *cstat,
                                          const ngtcp2_cc_pkt *pkt,
                                          ngtcp2_tstamp ts) {
  ngtcp2_cc_brutal *brutal = ngtcp2_struct_of(cc, ngtcp2_cc_brutal, cc);
  (void)ts;

  if (brutal->rate == 0) {
    /* Unarmed (handshake): plain ACK-clocked growth. */
    cstat->cwnd += pkt->pktlen;
    return;
  }

  ngtcp2_cc_brutal_update_cwnd(brutal, cstat);
}

static void ngtcp2_cc_brutal_congestion_event(ngtcp2_cc *cc,
                                              ngtcp2_conn_stat *cstat,
                                              ngtcp2_tstamp sent_ts,
                                              const ngtcp2_cc_ack *ack,
                                              ngtcp2_tstamp ts) {
  /* Never shrink on loss (see ngtcp2_cc_brutal_update_cwnd). */
  (void)cc;
  (void)cstat;
  (void)sent_ts;
  (void)ack;
  (void)ts;
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
  };

  cstat->cwnd = ngtcp2_cc_compute_initcwnd(cstat->max_tx_udp_payload_size);
}

void ngtcp2_cc_brutal_set_rate(ngtcp2_cc_brutal *brutal,
                               ngtcp2_conn_stat *cstat, uint64_t rate) {
  brutal->rate = rate;
  ngtcp2_cc_brutal_update_cwnd(brutal, cstat);
}
