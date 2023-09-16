/*
 * Internal interface definitions for the management interfaces
 *
 * This header is not part of the public library API and is thus not in
 * the public include folder
 */

#ifndef MANAGEMENT_H
#define MANAGEMENT_H 1

#include <n2n_typedefs.h>  // For the n2n_edge_t and n2n_sn_t defs
#include <stdbool.h>
#include <stddef.h>        // for size_t
#include <stdint.h>        // for uint64_t
#include <sys/types.h>     // for ssize_t
#include "n2n_define.h"    // for n2n_event_topic
#include "strbuf.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>    // for sockaddr, sockaddr_storage, socklen_t
#endif

enum n2n_mgmt_type {
    N2N_MGMT_UNKNOWN = 0,
    N2N_MGMT_READ = 1,
    N2N_MGMT_WRITE = 2,
    N2N_MGMT_SUB = 3,
};

/*
 * Everything needed to reply to a request
 *
 * TODO:
 * - one day, we might be able to merge the sss and eee members
 * - once eee and sss are merged, some fields should migrate back into it:
 *   - mgmt_sock
 *   - keep_running
 *   - mgmt_password_hash
 */
typedef struct mgmt_req {
    n2n_sn_t *sss;
    n2n_edge_t *eee;
    int mgmt_sock;                  // socket replies come from
    bool *keep_running;
    uint64_t mgmt_password_hash;
    enum n2n_mgmt_type type;
    char *argv0;
    char *argv;
    char tag[10];
    socklen_t sock_len;
    union {
        struct sockaddr sender_sock;
        struct sockaddr_storage sas;  // memory for the socket, actual socket can be longer than sockaddr
    };
} mgmt_req_t;

/*
 * Read/Write handlers are defined in this structure
 * TODO: DRY
 */
#define FLAG_WROK 1
typedef struct mgmt_handler {
    int flags;
    char  *cmd;
    char  *help;
    void (*func)(mgmt_req_t *req, strbuf_t *buf);
} mgmt_handler_t;

/*
 * Event topic names are defined in this structure
 */
typedef struct mgmt_events {
    enum n2n_event_topic topic;
    char  *cmd;
    char  *help;
} mgmt_events_t;

typedef size_t (mgmt_event_handler_t)(strbuf_t *buf, char *tag, int data0, void *data1);

// Lookup the index of matching argv0 in a cmd list
// store index in "Result", or -1 for not found
#define lookup_handler(Result, list, argv0) do { \
        int nr_max = sizeof(list) / sizeof(list[0]); \
        for( Result=0; Result < nr_max; Result++ ) { \
            if(0 == strcmp(list[Result].cmd, argv0)) { \
                break; \
            } \
        } \
        if( Result >= nr_max ) { \
            Result = -1; \
        } \
} while(0)

ssize_t send_reply (mgmt_req_t *req, strbuf_t *buf, size_t msg_len);
size_t gen_json_1str (strbuf_t *buf, char *tag, char *_type, char *key, char *val);
size_t gen_json_1uint (strbuf_t *buf, char *tag, char *_type, char *key, unsigned int val);
void send_json_1str (mgmt_req_t *req, strbuf_t *buf, char *_type, char *key, char *val);
void send_json_1uint (mgmt_req_t *req, strbuf_t *buf, char *_type, char *key, unsigned int val);

void mgmt_error (mgmt_req_t *req, strbuf_t *buf, char *msg);

void mgmt_stop (mgmt_req_t *req, strbuf_t *buf);
void mgmt_verbose (mgmt_req_t *req, strbuf_t *buf);
void mgmt_unimplemented (mgmt_req_t *req, strbuf_t *buf);

void mgmt_event_post2 (enum n2n_event_topic topic, int data0, void *data1, mgmt_req_t *debug, mgmt_req_t *sub, mgmt_event_handler_t fn);
void mgmt_help_row (mgmt_req_t *req, strbuf_t *buf, char *cmd, char *help);
void mgmt_help_events_row (mgmt_req_t *req, strbuf_t *buf, mgmt_req_t *sub, char *cmd, char *help);
int mgmt_auth (mgmt_req_t *req, char *auth);
bool mgmt_req_init2 (mgmt_req_t *req, strbuf_t *buf, char *cmdline);

#endif
