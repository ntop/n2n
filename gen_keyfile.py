#!/usr/bin/env python

# (c) 2009 Richard Andrews <andrews@ntop.org>

# Program to generate a n2n_edge key schedule file for twofish keys
# Each key line consists of the following element
# <from> <until> <txfrm> <opaque>
#
# where <from>, <until> are UNIX time_t values of key valid period
#       <txfrm> is the transform ID (=2 for twofish)
#       <opaque> is twofish-specific data as follows
# <sec_id>_<hex_key>

import os
import sys
import time
import random

NUM_KEYS=30
KEY_LIFE=300
KEY_LEN=16

now=time.time()
start_sa=random.randint( 0, 0xffffffff )

random.seed(now) # note now is a floating point time value

def rand_key():
    key=str()
    for i in range(0,KEY_LEN):
        key += "%02x"%( random.randint( 0, 255) )

    return key

for i in range(0,NUM_KEYS):
    from_time  = now + (KEY_LIFE * (i-1) )
    until_time = now + (KEY_LIFE * (i+1) )
    key = rand_key()
    sa_idx = start_sa + i
    transform_id = random.randint( 2, 3 )

    sys.stdout.write("%d %d %d %d_%s\n"%(from_time, until_time, transform_id,sa_idx, key) )


