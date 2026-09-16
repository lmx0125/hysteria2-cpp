  case NGTCP2_CC_ALGO_BRUTAL:
    ngtcp2_cc_brutal_init(&(*pconn)->brutal, &(*pconn)->log, &(*pconn)->cstat);

    break;
