/*
 * ngtcp2_cc_brutal is a fixed-rate, loss-insensitive congestion controller
 * (Hysteria's Brutal sender): the congestion window tracks
 * rate * smoothed_rtt * 2 / ack_rate, packet loss never shrinks it, and - the
 * part that makes it a *rate* controller rather than a window one - the
 * connection's pacer is programmed to the same rate, so the sender emits a
 * smooth stream instead of a burst per RTT.
 *
 * Arm it with ngtcp2_conn_set_brutal_rate() right after the connection is
 * created; an unarmed controller (rate == 0) only does ACK-clocked growth and
 * is meant to cover the handshake.
 *
 * Added by the ngtcp2_hy2_brutal_patch.
 */

/* brutal.go: pktInfoSlotCount / minSampleCount / minAckRate /
   congestionWindowMultiplier */
#define NGTCP2_BRUTAL_PKT_INFO_SLOT_COUNT 5
#define NGTCP2_BRUTAL_MIN_SAMPLE_COUNT 50
#define NGTCP2_BRUTAL_MIN_ACK_RATE 0.8
#define NGTCP2_BRUTAL_CWND_MULTIPLIER 2.0

typedef struct ngtcp2_cc_brutal_pkt_info {
  /* timestamp is the whole-second bucket this slot belongs to; a slot whose
     timestamp is older than the sampling window is stale and skipped. */
  int64_t timestamp;
  uint64_t ack_count;
  uint64_t loss_count;
} ngtcp2_cc_brutal_pkt_info;

typedef struct ngtcp2_cc_brutal {
  ngtcp2_cc cc;
  /* rate is the fixed send rate in bytes per second; 0 = unarmed. */
  uint64_t rate;
  /* ack_rate is the fraction of packets acknowledged over the last
     NGTCP2_BRUTAL_PKT_INFO_SLOT_COUNT seconds, clamped to
     [NGTCP2_BRUTAL_MIN_ACK_RATE, 1].  Both the window and the pacing rate are
     divided by it, so the *delivered* rate stays at the declared one on a
     lossy path.  This mirrors brutal.go's ackRate / disableLossCompensation. */
  double ack_rate;
  int loss_compensation_disabled;
  ngtcp2_cc_brutal_pkt_info pkt_info[NGTCP2_BRUTAL_PKT_INFO_SLOT_COUNT];
} ngtcp2_cc_brutal;

void ngtcp2_cc_brutal_init(ngtcp2_cc_brutal *brutal, ngtcp2_log *log,
                           ngtcp2_conn_stat *cstat);

void ngtcp2_cc_brutal_set_rate(ngtcp2_cc_brutal *brutal,
                               ngtcp2_conn_stat *cstat, uint64_t rate);

void ngtcp2_cc_brutal_set_loss_compensation(ngtcp2_cc_brutal *brutal,
                                            ngtcp2_conn_stat *cstat,
                                            int disabled);
