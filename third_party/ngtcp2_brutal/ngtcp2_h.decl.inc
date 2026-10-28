
/**
 * `ngtcp2_conn_set_brutal_rate` sets the fixed send rate (in bytes per
 * second) of a :enum:`NGTCP2_CC_ALGO_BRUTAL` connection, and programs the
 * connection pacer to the same rate.  Zero disarms it (plain ACK-clocked
 * growth until a rate is known).  Calling this on a connection with another
 * congestion controller switches it to Brutal.
 *
 * `disable_loss_compensation` pins the loss-compensation factor to 1 instead
 * of letting the measured ack rate inflate the window and the pacing rate.
 *
 * Added by the ngtcp2_hy2_brutal_patch.
 */
NGTCP2_EXTERN void ngtcp2_conn_set_brutal_rate(ngtcp2_conn *conn,
                                               uint64_t bytes_per_sec,
                                               int disable_loss_compensation);

/**
 * `ngtcp2_conn_get_pacing_interval_m` returns the active controller's pacing
 * interval in nanoseconds per byte, scaled by 1024 (the same unit as
 * `ngtcp2_conn_stat.pacing_interval_m`), or 0 when no pacing rate is set.
 *
 * The application uses it to size its send burst: ngtcp2 asks for
 * `ngtcp2_conn_get_send_quantum()` bytes per burst, but the controllers size
 * that at about 1 ms of data, and a period that short is paced badly by a
 * ~1 ms OS timer - the wake-up overshoot then exceeds half the period, which
 * is all ngtcp2's compensation can recover, and the achieved rate sags well
 * below the configured one. Multiplying the interval by the burst length
 * gives the period, so the application can widen the burst until the period
 * is comfortably longer than the timer.
 *
 * Added by the ngtcp2_hy2_brutal_patch.
 */
NGTCP2_EXTERN uint64_t ngtcp2_conn_get_pacing_interval_m(ngtcp2_conn *conn);
