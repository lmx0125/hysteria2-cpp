
/*
 * ngtcp2_conn_set_brutal_rate sets the fixed send rate (bytes per second) of
 * a connection and makes Brutal the active congestion controller.  The
 * application may only learn the negotiated rate after the handshake (e.g. a
 * server learns the client's declared receive rate in the auth request,
 * while the connection was created with the configured default algorithm).
 * Passing 0 disarms it.  Added by the ngtcp2_hy2_brutal_patch.
 */
void ngtcp2_conn_set_brutal_rate(ngtcp2_conn *conn, uint64_t bytes_per_sec) {
  if (conn->cc_algo != NGTCP2_CC_ALGO_BRUTAL) {
    /* The controllers live in a union: re-initializing the brutal member
     * installs its callbacks (replacing the previously active algorithm's)
     * and resets the window to the initial value, which then tracks
     * rate * srtt. */
    ngtcp2_cc_brutal_init(&conn->brutal, &conn->log, &conn->cstat);
    conn->cc_algo = NGTCP2_CC_ALGO_BRUTAL;
  }

  ngtcp2_cc_brutal_set_rate(&conn->brutal, &conn->cstat, bytes_per_sec);
}
