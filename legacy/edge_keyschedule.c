typedef struct n2n_tostat {
  uint8_t             can_tx;         /* Does this transop have a valid SA for encoding. */
  n2n_cipherspec_t    tx_spec;        /* If can_tx, the spec used to encode. */
} n2n_tostat_t;

typedef uint32_t n2n_sa_t;              /* security association number */
typedef int             (*n2n_transaddspec_f)( struct n2n_trans_op * arg, 
                                               const n2n_cipherspec_t * cspec );

typedef n2n_tostat_t    (*n2n_transtick_f)( struct n2n_trans_op * arg, 
                                            time_t now );

/** Read in a key-schedule file, parse the lines and pass each line to the
 *  appropriate trans_op for parsing of key-data and adding key-schedule
 *  entries. The lookup table of time->trans_op is constructed such that
 *  encoding can be passed to the correct trans_op. The trans_op internal table
 *  will then determine the best SA for that trans_op from the key schedule to
 *  use for encoding. */

static int edge_init_keyschedule(n2n_edge_t *eee) {
#define N2N_NUM_CIPHERSPECS 32

  int retval = -1;
  ssize_t numSpecs=0;
  n2n_cipherspec_t specs[N2N_NUM_CIPHERSPECS];
  size_t i;
  time_t now = time(NULL);

  numSpecs = n2n_read_keyfile(specs, N2N_NUM_CIPHERSPECS, eee->conf.keyschedule);

  if(numSpecs > 0)
    {
      traceEvent(TRACE_NORMAL, "keyfile = %s read -> %d specs.\n", optarg, (signed int)numSpecs);

      for (i=0; i < (size_t)numSpecs; ++i)
        {
	  n2n_transform_t idx = (n2n_transform_t) specs[i].t;
	  if(idx != eee->transop.transform_id) {
	    traceEvent(TRACE_ERROR, "changing transop in keyschedule is not supported");
	    retval = -1;
	  }

	  if(eee->transop.addspec != NULL)
	    retval = eee->transop.addspec(&eee->transop, &(specs[i]));

	  if (0 != retval)
            {
	      traceEvent(TRACE_ERROR, "keyschedule failed to add spec[%u] to transop[%d].\n",
			 (unsigned int)i, idx);

	      return retval;
            }
        }

      n2n_tick_transop(eee, now);
    }
  else    
    traceEvent(TRACE_ERROR, "Failed to process '%s'", eee->conf.keyschedule);
    
  return retval;
}

#if 0
  if(recvlen >= 6)
    {
      if(0 == memcmp(udp_buf, "reload", 6))
        {
	  if(strlen(eee->conf.keyschedule) > 0)
            {
	      if(edge_init_keyschedule(eee) == 0)
                {
		  msg_len=0;
		  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
				      "> OK\n");
		  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
			 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));
                }
	      return;
            }
        }
    }
#endif

#if 0
  case'K':
    {
      if(conf->encrypt_key) {
        traceEvent(TRACE_ERROR, "Error: -K and -k options are mutually exclusive");
        exit(1);
      } else {
        strncpy(conf->keyschedule, optargument, N2N_PATHNAME_MAXLEN-1);
        /* strncpy does not add NULL if the source has no NULL. */
        conf->keyschedule[N2N_PATHNAME_MAXLEN-1] = 0;
	      
        traceEvent(TRACE_NORMAL, "keyfile = '%s'\n", conf->keyschedule);
      }
      break;
    }
#endif

#if 0
  printf("-K <key file>            | Specify a key schedule file to load. Not with -k.\n");
#endif
