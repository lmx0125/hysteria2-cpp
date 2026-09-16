/*
 * ngtcp2_cc_brutal is a fixed-rate, loss-insensitive congestion controller
 * (Hysteria's Brutal sender): the congestion window tracks
 * rate * smoothed_rtt and packet loss never shrinks it, so a lossy long-RTT
 * path stays full instead of backing off.  Arm it with
 * ngtcp2_conn_set_brutal_rate() right after the connection is created; an
 * unarmed controller (rate == 0) only does ACK-clocked growth and is meant to
 * cover the handshake.
 *
 * Added by the ngtcp2_hy2_brutal_patch.
 */
typedef struct ngtcp2_cc_brutal {
  ngtcp2_cc cc;
  /* rate is the fixed send rate in bytes per second; 0 = unarmed. */
  uint64_t rate;
} ngtcp2_cc_brutal;

void ngtcp2_cc_brutal_init(ngtcp2_cc_brutal *brutal, ngtcp2_log *log,
                           ngtcp2_conn_stat *cstat);

void ngtcp2_cc_brutal_set_rate(ngtcp2_cc_brutal *brutal,
                               ngtcp2_conn_stat *cstat, uint64_t rate);
