#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "logger.h"
#include "ssl.h"
#include "util.h"

#ifdef PUBKEY_DATA_
#  include "pubkey_data_.h"
#endif
#ifdef ROOTPEM_DATA_
#  include "rootpem_data_.h"
#endif

#include <assert.h>
#include <stdint.h>

#define SSL_CIPHER_LIST_STR "ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,DHE-RSA-AES128-GCM-SHA256,AES128-GCM-SHA256,ECDHE-ECDSA-AES256-SHA,ECDHE-RSA-AES256-SHA,DHE-RSA-AES256-SHA,AES256-SHA,ECDHE-ECDSA-RC4-SHA,ECDHE-ECDSA-AES128-SHA,ECDHE-RSA-RC4-SHA,ECDHE-RSA-AES128-SHA,DHE-RSA-AES128-SHA,DHE-DSS-AES128-SHA,RC4-SHA,RC4-MD5,AES128-SHA,DES-CBC3-SHA"
//"ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,"

int ssl_log_errors(enum LogLevel level, const char *name)
{
	int count = 0;
	int err;
	while ((err = ERR_get_error())) {
		const char *msg = (const char*)ERR_reason_error_string(err);
		const char *lib = (const char*)ERR_lib_error_string(err);
		const char *func = (const char*)ERR_func_error_string(err);
		LogLog(level, name, "%s in %s %s\n", msg, lib, func);
		count++;
	}
	return count;
}

int ssl_init(struct telex_conf *conf)
{
	if (conf->ssl_ctx) {
		LogTrace("ssl", "already init'ed");
		return 0; // already init'ed
	}
	LogTrace("ssl", "ssl_init");

	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	if (RAND_poll() == 0) {
		ssl_log_errors(LOG_FATAL, "ssl");
		LogFatal("ssl", "RAND_poll() failed; shutting down");
		return -1;
	}

	conf->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
    SSL_CTX_set_cipher_list(conf->ssl_ctx, SSL_CIPHER_LIST_STR);
	if (!conf->ssl_ctx) {
		ssl_log_errors(LOG_FATAL, "ssl");
		LogError("ssl", "Could not initialize context");
		return -1;
	}

    // Load the CAs we trust
    if (!SSL_CTX_load_verify_locations(conf->ssl_ctx, conf->ca_list, 0)) {
		ssl_log_errors(LOG_FATAL, "ssl");
		LogFatal("ssl", "Could not read CA list file %s", conf->ca_list);
		return -1;
	}

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	LogInfo("ssl", "Older version; setting SSL_CTX_set_verify_depth");
	SSL_CTX_set_verify_depth(conf->ssl_ctx,1);
#endif

/*
    // Tag init
#ifdef PUBKEY_DATA_
	if (conf->keyfile) {
	  tag_load_pubkey(conf->keyfile);
	} else {
	  tag_load_pubkey_bytes(pubkey_data_, sizeof(pubkey_data_)-1);
	}
#else
	tag_load_pubkey(conf->keyfile);
#endif
*/

    return 0;
}

void ssl_done(struct telex_conf *conf)
{
	if (conf->ssl_ctx) {
		SSL_CTX_free(conf->ssl_ctx);
	}
}

// Creates a new SSL connection object in state->ssl and
// initializes it for a Telex connection.
// Returns 0 on successful Telex initialization; nonzero otherwise.
int ssl_new_telex(struct telex_state *state)
{
	state->ssl = SSL_new(state->conf->ssl_ctx);
	if (!state->ssl) {
		ssl_log_errors(LOG_ERROR, state->name);
		LogError(state->name, "Could not create new telex SSL object");
		return -1;
	}

    //unsigned long t = htonl(time(NULL));

    /*
    unsigned char tag_context[MAX_CONTEXT_LEN];
    memcpy(&tag_context[0], &server_ip, 4);
    memcpy(&tag_context[4], &t, 4);
    memcpy(&tag_context[8], session_id, 1);

	gen_tag(state->tag, state->secret, tag_context, MAX_CONTEXT_LEN);
	HexDump(LOG_TRACE, state->name, "tag", state->tag, sizeof(Tag));
	HexDump(LOG_TRACE, state->name, "secret", state->secret, sizeof(Secret));

    // Load the client random: 4 bytes of timestamp + 28 bytes of tag
    state->ssl->telex_client_random = malloc(32);
    memcpy(state->ssl->telex_client_random, &t, 4);
	memcpy(state->ssl->telex_client_random+4, state->tag, sizeof(Tag));

	state->ssl->telex_dh_priv_key = telex_ssl_get_dh_key(state->secret, NULL);
    */

	return 0;
}
