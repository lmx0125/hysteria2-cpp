
/**
 * `ngtcp2_conn_set_brutal_rate` sets the fixed send rate (in bytes per
 * second) of a :enum:`NGTCP2_CC_ALGO_BRUTAL` connection.  Zero disarms it
 * (plain ACK-clocked growth until a rate is known).  Calling this on a
 * connection with another congestion controller is a no-op.
 * Added by the ngtcp2_hy2_brutal_patch.
 */
NGTCP2_EXTERN void ngtcp2_conn_set_brutal_rate(ngtcp2_conn *conn,
                                               uint64_t bytes_per_sec);
