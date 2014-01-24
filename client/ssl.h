#ifndef _TELEXSSL_H_
#define _TELEXSSL_H_

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "logger.h"
#include "state.h"

// Initialize SSL engine based on settings from conf
int ssl_init(struct telex_conf *conf);

// Log any queued SSL errors from the current thread
// at the given LogLevel
int ssl_log_errors(enum LogLevel level, const char *name);

// Clean up SSL contexts
void ssl_done(struct telex_conf *conf);

int ssl_new_telex(struct telex_state *state);

#endif//_TELEXSSL_H_
