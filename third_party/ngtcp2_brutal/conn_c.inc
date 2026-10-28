
/*
 * ngtcp2_conn_set_brutal_rate sets the fixed send rate (bytes per second) of
 * a connection and makes Brutal the active congestion controller.  The
 * application may only learn the negotiated rate after the handshake (e.g. a
 * server learns the client's declared receive rate in the auth request,
 * while the connection was created with the configured default algorithm).
 * Passing 0 disarms it.
 *
 * disable_loss_compensation mirrors Hysteria's BandwidthConfig field of the
 * same name: when set, ack_rate stays at 1 and neither the window nor the
 * pacing rate is inflated on a lossy path.
 *
 * Added by the ngtcp2_hy2_brutal_patch.
 */
void ngtcp2_conn_set_brutal_rate(ngtcp2_conn *conn, uint64_t bytes_per_sec,
                                 int disable_loss_compensation) {
  if (conn->cc_algo != NGTCP2_CC_ALGO_BRUTAL) {
    /* The controllers live in a union: re-initializing the brutal member
     * installs its callbacks (replacing the previously active algorithm's)
     * and resets the window to the initial value, which then tracks
     * rate * srtt. */
    ngtcp2_cc_brutal_init(&conn->brutal, &conn->log, &conn->cstat);
    conn->cc_algo = NGTCP2_CC_ALGO_BRUTAL;
  }

  ngtcp2_cc_brutal_set_loss_compensation(&conn->brutal, &conn->cstat,
                                         disable_loss_compensation);
  ngtcp2_cc_brutal_set_rate(&conn->brutal, &conn->cstat, bytes_per_sec);
}

/*
 * See ngtcp2.h.  Exposes the active controller's pacing interval so the
 * application can size its send burst to a period its timer can actually
 * pace.  Added by the ngtcp2_hy2_brutal_patch.
 */
uint64_t ngtcp2_conn_get_pacing_interval_m(ngtcp2_conn *conn) {
  return conn->cstat.pacing_interval_m;
}
