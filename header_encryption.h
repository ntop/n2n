#include <stdint.h>


#include "n2n.h"
#include "speck.h"


typedef struct speck_context_t he_context_t;


/* Header encryption indicators */
#define HEADER_ENCRYPTION_UNKNOWN       0
#define HEADER_ENCRYPTION_NONE          1
#define HEADER_ENCRYPTION_ENABLED       2


uint32_t packet_header_decrypt (uint8_t packet[], uint8_t packet_len,
                                char * community_name, he_context_t * ctx);


int8_t packet_header_decrypt_if_required (uint8_t packet[], uint16_t packet_len,
                                          struct sn_community * communities);


int32_t packet_header_encrypt (uint8_t packet[], uint8_t header_len, he_context_t * ctx);


void packet_header_setup_key (char * community_name, he_context_t * ctx);
