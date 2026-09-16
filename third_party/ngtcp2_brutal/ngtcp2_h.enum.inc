/**
 * :enum:`NGTCP2_CC_ALGO_BRUTAL` is a fixed-rate, loss-insensitive congestion
 * controller (Hysteria's Brutal sender): the window tracks rate *
 * smoothed_rtt and packet loss never shrinks it, so a lossy long-RTT path
 * stays full instead of backing off.  Use
 * `ngtcp2_conn_set_brutal_rate` to arm it after the handshake.
 * Added by the ngtcp2_hy2_brutal_patch.
 */
NGTCP2_CC_ALGO_BRUTAL = 0x03
