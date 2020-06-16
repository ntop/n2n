#include <stdint.h>

#include "speck.h"
typedef speck_context_t he_context_t;


#define HEADER_ENCRYPTION_UNKNOWN       0
#define HEADER_ENCRYPTION_NONE          1
#define HEADER_ENCRYPTION_ENABLED       2


uint32_t decrypt_packet_header (uint8_t packet[], uint8_t packet_len,
                                char * community_name, he_context_t * ctx);

int32_t encryt_packet_header (uint8_t packet[], uint8_t header_len, he_context_t * ctx);

int32_t encryt_packet_header (uint8_t packet[], uint8_t header_len, he_context_t * ctx);
