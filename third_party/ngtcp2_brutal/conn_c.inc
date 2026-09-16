
/*
 * ngtcp2_conn_set_brutal_rate sets the fixed send rate (bytes per second) of
 * a NGTCP2_CC_ALGO_BRUTAL connection; 0 disarms it.  No-op for any other
 * congestion controller.  Added by the ngtcp2_hy2_brutal_patch.
 */
void ngtcp2_conn_set_brutal_rate(ngtcp2_conn *conn, uint64_t bytes_per_sec) {
  if (conn->cc_algo != NGTCP2_CC_ALGO_BRUTAL) {
    return;
  }

  ngtcp2_cc_brutal_set_rate(&conn->brutal, &conn->cstat, bytes_per_sec);
}
