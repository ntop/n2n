/*
 * Common routines shared between the management interfaces
 *
 */


#include <pearson.h>     // for pearson_hash_64
#include <stdbool.h>
#include <stdio.h>       // for snprintf, NULL, size_t
#include <stdlib.h>      // for strtoul
#include <string.h>      // for strtok, strlen, strncpy
#include "management.h"
#include "n2n.h"         // for TRACE_DEBUG, traceEvent

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <netdb.h>       // for getnameinfo, NI_NUMERICHOST, NI_NUMERICSERV
#include <sys/socket.h>  // for sendto, sockaddr
#endif


// TODO: move logging defs in their own header and include that
void setTraceLevel (int level);
int getTraceLevel ();

ssize_t send_reply (mgmt_req_t *req, strbuf_t *buf, size_t msg_len) {
    // TODO: better error handling (counters?)
    return sendto(req->mgmt_sock, buf->str, msg_len, 0,
                  &req->sender_sock, req->sock_len);
}

size_t gen_json_1str (strbuf_t *buf, char *tag, char *_type, char *key, char *val) {
    return snprintf(buf->str, buf->size,
                    "{"
                    "\"_tag\":\"%s\","
                    "\"_type\":\"%s\","
                    "\"%s\":\"%s\"}\n",
                    tag,
                    _type,
                    key,
                    val);
}

size_t gen_json_1uint (strbuf_t *buf, char *tag, char *_type, char *key, unsigned int val) {
    return snprintf(buf->str, buf->size,
                    "{"
                    "\"_tag\":\"%s\","
                    "\"_type\":\"%s\","
                    "\"%s\":%u}\n",
                    tag,
                    _type,
                    key,
                    val);
}

void send_json_1str (mgmt_req_t *req, strbuf_t *buf, char *_type, char *key, char *val) {
    size_t msg_len = gen_json_1str(buf, req->tag, _type, key, val);
    send_reply(req, buf, msg_len);
}

void send_json_1uint (mgmt_req_t *req, strbuf_t *buf, char *_type, char *key, unsigned int val) {
    size_t msg_len = gen_json_1uint(buf, req->tag, _type, key, val);
    send_reply(req, buf, msg_len);
}

void mgmt_error (mgmt_req_t *req, strbuf_t *buf, char *msg) {
    send_json_1str(req, buf, "error", "error", msg);
}

void mgmt_stop (mgmt_req_t *req, strbuf_t *buf) {

    if(req->type==N2N_MGMT_WRITE) {
        *req->keep_running = false;
    }

    send_json_1uint(req, buf, "row", "keep_running", *req->keep_running);
}

void mgmt_verbose (mgmt_req_t *req, strbuf_t *buf) {

    if(req->type==N2N_MGMT_WRITE) {
        if(req->argv) {
            setTraceLevel(strtoul(req->argv, NULL, 0));
        }
    }

    send_json_1uint(req, buf, "row", "traceLevel", getTraceLevel());
}

void mgmt_unimplemented (mgmt_req_t *req, strbuf_t *buf) {

    mgmt_error(req, buf, "unimplemented");
}

void mgmt_event_post2 (enum n2n_event_topic topic, int data0, void *data1, mgmt_req_t *debug, mgmt_req_t *sub, mgmt_event_handler_t fn) {
    traceEvent(TRACE_DEBUG, "post topic=%i data0=%i", topic, data0);

    if( sub->type != N2N_MGMT_SUB && debug->type != N2N_MGMT_SUB) {
        // If neither of this topic or the debug topic have a subscriber
        // then we dont need to do any work
        return;
    }

    char buf_space[100];
    strbuf_t *buf;
    STRBUF_INIT(buf, buf_space, sizeof(buf_space));

    char *tag;
    if(sub->type == N2N_MGMT_SUB) {
        tag = sub->tag;
    } else {
        tag = debug->tag;
    }

    size_t msg_len = fn(buf, tag, data0, data1);

    if(sub->type == N2N_MGMT_SUB) {
        send_reply(sub, buf, msg_len);
    }
    if(debug->type == N2N_MGMT_SUB) {
        send_reply(debug, buf, msg_len);
    }
    // TODO:
    // - ideally, we would detect that the far end has gone away and
    //   set the ->type back to N2N_MGMT_UNKNOWN, but we are not using
    //   a connected socket, so that is difficult
    // - failing that, we should require the client to send an unsubscribe
    //   and provide a manual unsubscribe
}

void mgmt_help_row (mgmt_req_t *req, strbuf_t *buf, char *cmd, char *help) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"cmd\":\"%s\","
                       "\"help\":\"%s\"}\n",
                       req->tag,
                       cmd,
                       help);

    send_reply(req, buf, msg_len);
}

void mgmt_help_events_row (mgmt_req_t *req, strbuf_t *buf, mgmt_req_t *sub, char *cmd, char *help) {
    size_t msg_len;
    char host[40];
    char serv[6];

    if((sub->type != N2N_MGMT_SUB) ||
       getnameinfo((struct sockaddr *)&sub->sender_sock, sizeof(sub->sender_sock),
                   host, sizeof(host),
                   serv, sizeof(serv),
                   NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
        host[0] = '?';
        host[1] = 0;
        serv[0] = '?';
        serv[1] = 0;
    }

    // TODO: handle a topic with no subscribers more cleanly

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"topic\":\"%s\","
                       "\"tag\":\"%s\","
                       "\"sockaddr\":\"%s:%s\","
                       "\"help\":\"%s\"}\n",
                       req->tag,
                       cmd,
                       sub->tag,
                       host, serv,
                       help);

    send_reply(req, buf, msg_len);
}

// TODO: work out a method to keep the mgmt_handlers defintion const static,
// and then import the shared mgmt_help () definition to this file

/*
 * Check if the user is authorised for this command.
 * - this should be more configurable!
 * - for the moment we use some simple heuristics:
 *   Reads are not dangerous, so they are simply allowed
 *   Writes are possibly dangerous, so they need a fake password
 */
int mgmt_auth (mgmt_req_t *req, char *auth) {

    if(auth) {
        /* If we have an auth key, it must match */
        if(req->mgmt_password_hash == pearson_hash_64((uint8_t*)auth, strlen(auth))) {
            return 1;
        }
        return 0;
    }
    /* if we dont have an auth key, we can still read */
    if(req->type == N2N_MGMT_READ) {
        return 1;
    }

    return 0;
}

/*
 * Handle the common and shred parts of the mgmt_req_t initialisation
 */
void mgmt_req_init2 (mgmt_req_t *req, strbuf_t *buf, char *cmdline) {
    char *typechar;
    char *options;
    char *flagstr;
    int flags;
    char *auth;

    /* Initialise the tag field until we extract it from the cmdline */
    req->tag[0] = '-';
    req->tag[1] = '1';
    req->tag[2] = '\0';

    typechar = strtok(cmdline, " \r\n");
    if(!typechar) {
        /* should not happen */
        mgmt_error(req, buf, "notype");
        return;
    }
    if(*typechar == 'r') {
        req->type=N2N_MGMT_READ;
    } else if(*typechar == 'w') {
        req->type=N2N_MGMT_WRITE;
    } else if(*typechar == 's') {
        req->type=N2N_MGMT_SUB;
    } else {
        mgmt_error(req, buf, "badtype");
        return;
    }

    /* Extract the tag to use in all reply packets */
    options = strtok(NULL, " \r\n");
    if(!options) {
        mgmt_error(req, buf, "nooptions");
        return;
    }

    req->argv0 = strtok(NULL, " \r\n");
    if(!req->argv0) {
        mgmt_error(req, buf, "nocmd");
        return;
    }

    /*
     * The entire rest of the line is the argv. We apply no processing
     * or arg separation so that the cmd can use it however it needs.
     */
    req->argv = strtok(NULL, "\r\n");

    /*
     * There might be an auth token mixed in with the tag
     */
    char *tagp = strtok(options, ":");
    strncpy(req->tag, tagp, sizeof(req->tag)-1);
    req->tag[sizeof(req->tag)-1] = '\0';

    flagstr = strtok(NULL, ":");
    if(flagstr) {
        flags = strtoul(flagstr, NULL, 16);
    } else {
        flags = 0;
    }

    /* Only 1 flag bit defined at the moment - "auth option present" */
    if(flags & 1) {
        auth = strtok(NULL, ":");
    } else {
        auth = NULL;
    }

    if(!mgmt_auth(req, auth)) {
        mgmt_error(req, buf, "badauth");
        return;
    }
}
