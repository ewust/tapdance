#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WIN32
#include <ctype.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <io.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "logger.h"
#include "proxy.h"
#include "ssl.h"
#include "state.h"
#include "util.h"
#include "gcm.h"
#include "elligator2.h"

void first_read_cb(struct bufferevent *bev, struct telex_state *state);
static void read_cb(struct bufferevent *, struct telex_state *);
void remote_read_cb(struct bufferevent *bev, struct telex_state *state);
static void event_cb(struct bufferevent *, short, struct telex_state *);
static void drained_write_cb(struct bufferevent *, struct telex_state *);
static void close_on_finished_write_cb(struct bufferevent *, void *arg);

#define MAX_OUTPUT_BUFFER (512*1024)

/* I don't know why the fuck gcc can't seem to find this.
  _EVENT_HAVE_OPENSSL is set to 1 in /usr/include/event2/event-config.h,
 and event2/bufferevent_ssl.h is present. */
struct bufferevent *
bufferevent_openssl_filter_new(struct event_base *base,
    struct bufferevent *underlying,
    struct ssl_st *ssl,
    enum bufferevent_ssl_state state,
    int options);

// Simple resource counters
// (help with debugging memory leaks)
int __ref_BEV = 0;
int __ref_STATE = 0;
int __ref_SSL = 0;
#define _inc(_resource) \
	__ref_##_resource++; \
	LogTrace("proxy", "%s ++ : %d", #_resource, __ref_##_resource);	
#define _dec(_resource, ptr) \
	assert(ptr); __ref_##_resource--; assert(__ref_##_resource >= 0);\
	LogTrace("proxy", "%s -- : %d", #_resource, __ref_##_resource);


void get_random_conn_id(struct telex_state *state)
{
    int f = open("/dev/urandom", 'r');
    size_t rlen = 0;
    while (rlen < sizeof(state->remote_conn_id)) {
        int r = read(f, &state->remote_conn_id[rlen], sizeof(state->remote_conn_id) - rlen);
        if (r < 0) {
            LogError(state->name, "Error reading /dev/urandom...");
        }
        rlen += r;
    }
    close(f);
}

// Allocate and initialize tunnel connection State object
struct telex_state *StateInit(struct telex_conf *conf)
{
	struct telex_state *state;
	_inc(STATE); state = calloc(1, sizeof(struct telex_state));
	assert(state);
	state->conf = conf;
	state->id = state->conf->count_tunnels++;
	state->conf->count_open_tunnels++;
	state->start_ms = time_ms();
	snprintf(state->name, sizeof(state->name), "tunnel %u", state->id); 

    // Random conn_id
    get_random_conn_id(state);

	LogInfo(state->name, "Opened (%u active)", state->conf->count_open_tunnels);
	return state;
}

// Only cleans up the remote connection and SSL objects (the good parts)
// leaving the local proxy intact
void cleanup_ssl(struct telex_state *state)
{
	if (state->remote) {
		_dec(BEV, state->remote);
		bufferevent_free(state->remote);
		state->remote = NULL;
	}
	if (state->remotetcp) {
		_dec(BEV, state->remotetcp);
		bufferevent_free(state->remotetcp);
		state->remotetcp = NULL;
	}
	if (state->ssl) {
		_dec(SSL, state->ssl);
		SSL_free(state->ssl);
		state->ssl = NULL;
	}
}

// Deallocate dynamic structures, close socket,
// and free State object itself.
// Please add cleanup code here if you extend
// the structure!
void StateCleanup(struct telex_state **_state)
{
	if (!_state || !_state)
		return;
	struct telex_state *state = *_state;
	*_state = NULL;

	if (state->local) {
		_dec(BEV, state->local);
		bufferevent_free(state->local);
		state->local = NULL;
	}
    cleanup_ssl(state);

	// TODO: Do we have to close the sockets?	

	state->conf->count_open_tunnels--;
	unsigned long long duration = time_ms() - state->start_ms;
	LogInfo(state->name, "Closed (%u active); %ld up  %ld down  %0.3f s",
		state->conf->count_open_tunnels,
		state->in_local, state->in_remote,
		duration/1000.);
	_dec(STATE, state); free(state);
}


// Finish what proxy_accept_cb started - but now we know the
// notblocked_host's ip (server_ip).
void proxy_notblocked_getaddrinfo_cb(int result, struct evutil_addrinfo *ai,
                                     struct telex_state *state)
{
    assert(state != NULL);
    assert(result);
    if (ai == NULL) {
        LogError(state->name, "Lookup of notblocked failed (do you have Internet?)");
        StateCleanup(&state);
        return;
    }

    struct in_addr *server_ip = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
    assert(server_ip);

}

// This starts a new TCP/TLS connection to notblocked
// It is called both when a new local proxy connection is accepted
// and when we need to re-open an existing telex transport (state->local is reused)
void make_new_telex_conn(struct telex_state *state)
{
    struct telex_conf *conf = state->conf;

    HexDump(LOG_TRACE, state->name, "Opening telex id:", state->remote_conn_id, sizeof(state->remote_conn_id));

	state->remotetcp = bufferevent_socket_new(state->base, -1,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if (!state->remotetcp) {
		LogError(state->name, "Could not create remote bufferevent socket");
		StateCleanup(&state);
		return;
	}
	_inc(BEV);

    // TODO: make nonblocking lookup?
    bufferevent_socket_connect_hostname(state->remotetcp, NULL, AF_INET, conf->notblocked_host, conf->notblocked_port);

    // After resolution...
    /*
    struct sockaddr_in sin;
    if (getpeername(bufferevent_getfd(state->remotetcp), (struct sockaddr *)&sin, (socklen_t*)sizeof(sin)) < 0) {
        perror("getpeername");
        LogError("proxy", "getpeername failed");
        StateCleanup(&state);
        return;
    }
    char ip_p[INET_ADDRSTRLEN];
    LogTrace(state->name, "Connecting to %s:%d",
             evutil_inet_ntop(AF_INET, server_ip, ip_p, sizeof(ip_p)), state->conf->notblocked_port);
    //bufferevent_socket_connect(state->remotetcp, ai->ai_addr, (int)ai->ai_addrlen);
    */

	if (ssl_new_telex(state) < 0) {
		ssl_log_errors(LOG_ERROR, state->name);
		LogError(state->name, "Could not create new telex SSL connection object");
		StateCleanup(&state);
		return;
	}
	_inc(SSL);

	state->remote = bufferevent_openssl_filter_new(state->base, state->remotetcp,
		state->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
		// Not BEV_OPT_CLOSE_ON_FREE!
	if (!state->remote) {
		LogError(state->name, "Could not create remote SSL bufferevent filter");
		StateCleanup(&state);
		return;
	}
	_inc(BEV);

    // First, set our read_cb to something that receives the SPTelex init message
	bufferevent_setcb(state->remote, (bufferevent_data_cb)first_read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);

    // Disable until SPTelex init msg
    bufferevent_disable(state->local, EV_READ|EV_WRITE);
	bufferevent_setcb(state->local, (bufferevent_data_cb)read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);

    // Hmm...we should make a second one of these
    state->in_local = 0;
}

// We've accepted a connection for proxying...
// Establish a connection to server specified in conf
// and set up events to relay traffic in both directions.
void proxy_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                     __attribute__((unused)) struct sockaddr *address, __attribute__((unused)) int socklen,
                     struct telex_conf *conf)
{
	LogTrace("proxy", "ACCEPT");

	// Init connection state
	struct telex_state *state = StateInit(conf);
	state->base = evconnlistener_get_base(listener);

	state->local = bufferevent_socket_new(state->base, fd,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if (!state->local) {
		LogError(state->name, "Could not create local bufferevent socket");
		StateCleanup(&state);
		return;
	}
	_inc(BEV);

    make_new_telex_conn(state);
}

    /*
    char portbuf[10];
    struct evutil_addrinfo hint;

    evutil_snprintf(portbuf, sizeof(portbuf), "%d", conf->notblocked_port);

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_socktype = SOCK_STREAM;

    LogTrace(state->name, "Resolving %s", conf->notblocked_host);
    evutil_getaddrinfo_async(conf->dns_base, conf->notblocked_host,
                portbuf, &hint, proxy_notblocked_getaddrinfo_cb, state);
    */

#define ISLOCAL(bev, state) ((bev) == (state)->local)
#define ISREMOTE(bev, state) ((bev) == (state)->remote)
#define PARTY(bev, state) (ISLOCAL((bev),(state)) ? "local" : \
	(ISREMOTE((bev),(state)) ? "remote" : "other" ))

// TODO: common.h
struct init_msg_st {
    uint8_t type;
    uint16_t len;
    uint16_t magic_val; // Prevent accidental init
    uint16_t win_size;
} __attribute__((packed));
#define SPTELEX_MAGIC_VAL 0x2a75
enum { MSG_DATA=0, MSG_INIT, MSG_RECONNECT, MSG_CLOSE };

void first_read_cb(struct bufferevent *bev, struct telex_state *state)
{
    struct evbuffer *src = bufferevent_get_input(bev);
    struct init_msg_st msg;
    if (evbuffer_get_length(src) < sizeof(msg)) {
        return;
    }

    LogTrace(state->name, "first_read %d bytes", evbuffer_get_length(src));

    evbuffer_remove(src, &msg, sizeof(msg));

    if (msg.type != MSG_INIT || ntohs(msg.magic_val) != SPTELEX_MAGIC_VAL) {
        // Not Telex, end this connection
        LogWarn(state->name, "Failed to get a SPTelex init msg (not using a Telex server, or it's not running?) Got: %04x", msg.magic_val);
        StateCleanup(&state);
        return;
    }

    state->max_send = ntohs(msg.win_size);
    LogTrace(state->name, "Got SPTelex init, window: %d; %d bytes to read from local",
             state->max_send, evbuffer_get_length(bufferevent_get_input(state->local)));

    // Set up to start passing between proxy and client
	bufferevent_setcb(state->remote, (bufferevent_data_cb)remote_read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);

    // Allow local proxy to start sending data
	bufferevent_enable(state->local,  EV_READ|EV_WRITE);

    if (evbuffer_get_length(bufferevent_get_input(state->local))) {
        // bytes left to read from last time in local;
        // event might not fire, so we'll call it ourselves
        read_cb(state->local, state);
    }
}

struct msg_hdr {
    uint8_t msg_type;
    uint16_t msg_len;
} __attribute__((packed));
// Parse header
//      uint8_t     msg_type;
//      uint16_t    msg_len;
//      char        msg[msg_len];
void remote_read_cb(struct bufferevent *bev, struct telex_state *state)
{
    assert(bev == state->remote);
    struct evbuffer *src = bufferevent_get_input(bev);
    uint8_t msg_type;
    uint16_t msg_len;
    struct msg_hdr msg;
    size_t buffer_len = evbuffer_get_length(src);

    while (buffer_len) {

        if (buffer_len < sizeof(msg_type)) {
            return;
        }

        evbuffer_copyout(src, &msg_type, sizeof(msg_type));

        switch (msg_type) {
        case MSG_DATA:
            // Read message length from header
            if (buffer_len < sizeof(msg)) {
                return;
            }
            evbuffer_copyout(src, &msg, sizeof(msg));
            msg_len = ntohs(msg.msg_len);
            if ((buffer_len - sizeof(msg)) < msg_len) {
                return;
            }
            // Eat header
            evbuffer_drain(src, sizeof(msg));

            // Book keeping
		    state->in_remote += msg_len;
            LogTrace(state->name, "READCB remote: MSG_DATA buflen: %d (got %lu bytes / %lu bytes so far)",
                     buffer_len, msg_len, state->in_remote);

            evbuffer_remove_buffer(src, bufferevent_get_output(state->local), msg_len);
            break;

        case MSG_RECONNECT:
            evbuffer_drain(src, sizeof(msg_type));
            LogTrace(state->name, "READCB remote: MSG_RECONNECT");
            state->retry_conn = 1;
            bufferevent_disable(state->local, EV_READ);
            cleanup_ssl(state);
            make_new_telex_conn(state);
            break;

        case MSG_CLOSE:
            evbuffer_drain(src, sizeof(msg_type));
            LogTrace(state->name, "READCB remote: MSG_CLOSE %d bytes read pending, %d bytes write pending",
                     evbuffer_get_length(bufferevent_get_input(state->remote)),
                     evbuffer_get_length(bufferevent_get_output(state->local)));
            state->retry_conn = 0;
            bufferevent_flush(state->local, EV_WRITE, BEV_FINISHED);
            bufferevent_setcb(state->local, NULL, close_on_finished_write_cb,
			                  (bufferevent_event_cb)event_cb, state);
            LogTrace(state->name, "now we have %d bytes write pending",
                     evbuffer_get_length(bufferevent_get_output(state->local)));
            //StateCleanup(&state);
            break;

        default:
            evbuffer_drain(src, sizeof(msg_type));  // What else is there to do???
            LogError(state->name, "Got invalid MSG_TYPE=%02x", msg_type);
            break;
        }

        buffer_len = evbuffer_get_length(src);
    }

}

// This is for when our local connection EOFs or ERRORs,
// and we want to do a (flushed) shutdown of the Telex connection
// Otherwise, calling StateCleanup too early will free/close
// things before pending data can be flushed
void tcpdone_final(__attribute__((unused)) struct bufferevent *bev,
                   __attribute__((unused)) short events, void *arg)
{
    struct telex_state *state = arg;
    StateCleanup(&state);
}

// This is called when we are closing the telex connection
// and the underlying TCP connection has closed
// We can then safely open a new telex connection in its place
// (with the same conn_id) and resume forwarding data
void tcpdone(__attribute__((unused)) struct bufferevent *bev,
             __attribute__((unused)) short events, void *arg)
{
    struct telex_state *state = arg;
    LogTrace(state->name, "i got your close event right here");

    cleanup_ssl(state);
    make_new_telex_conn(state);
}

// Call this if you'd like to flush the rest of the data in the remote pipe,
// and set a callback for when it's closed to start a new connection in its place.
void close_ssl(struct telex_state *state)
{

    SSL_set_shutdown(state->ssl, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(state->ssl);
    bufferevent_flush(state->remote, EV_WRITE, BEV_FINISHED);
    bufferevent_flush(state->remotetcp, EV_WRITE, BEV_FINISHED);

    bufferevent_setcb(state->remotetcp, NULL, NULL, tcpdone, state);

    LogDebug(state->name, "%d to read, %d to write", evbuffer_get_length(bufferevent_get_input(state->local)),
            evbuffer_get_length(bufferevent_get_output(state->remote)));
    //cleanup_ssl(state);
    //make_new_telex_conn(state);

}

// Read local
void read_cb(struct bufferevent *bev, struct telex_state *state)
{
	struct bufferevent *partner =
			ISLOCAL(bev,state) ? state->remote : state->local;

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	size_t total = 0;
	if (ISLOCAL(bev,state)) {
        if ((state->in_local + len) > state->max_send) {
            LogDebug(state->name, "about to exceed send window (%d + %d > %d); starting new connection, with %d bytes left to send",
                                state->in_local, len, state->max_send,
                                evbuffer_get_length(bufferevent_get_output(partner)));

            // I think we want to send a close event, but wait for it to go through...?
            close_ssl(state);
            bufferevent_disable(state->local, EV_READ);
            //cleanup_ssl(state);
            //make_new_telex_conn(state);
            return;
        }

		total = (state->in_local += len);
	} else if (ISREMOTE(bev,state)) {
        LogError(state->name, "you shouldn't be here");
		total = (state->in_remote += len);
	} else {
		assert(0);
	}

	LogTrace(state->name, "READCB %s (got %lu bytes / %lu so far)", 
		PARTY(bev,state), (unsigned long)len, total);

	if (!partner) {
		LogTrace(state->name, "Partner missing; discarding data");
		evbuffer_drain(src, len);
		return;
	}

	struct evbuffer *dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src); // copy from input to output

	if (evbuffer_get_length(dst) >= MAX_OUTPUT_BUFFER) {
		LogDebug(state->name, "PAUSING (dst: %d bytes)", 
			evbuffer_get_length(dst));
		bufferevent_setcb(partner,
			(bufferevent_data_cb)read_cb,
			(bufferevent_data_cb)drained_write_cb,
			(bufferevent_event_cb)event_cb, state);
		bufferevent_setwatermark(partner, EV_WRITE,
				MAX_OUTPUT_BUFFER/2, MAX_OUTPUT_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
}

void drained_write_cb(struct bufferevent *bev, struct telex_state *state)
{
	LogDebug(state->name, "DRAINING %s", PARTY(bev,state));
	struct bufferevent *partner =
			ISLOCAL(bev,state) ? state->remote : state->local;
	bufferevent_setcb(bev, (bufferevent_data_cb)read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner) {
		bufferevent_enable(partner, EV_READ);
	}
}

void close_on_finished_write_cb(struct bufferevent *bev, void *arg)
{
    struct telex_state *state = arg;
	struct evbuffer *b = bufferevent_get_output(bev);
	LogDebug(state->name, "CLOSE_ON_FINISHED %s (%d bytes remaining)", 
		PARTY(bev,state), evbuffer_get_length(b));
	if (evbuffer_get_length(b) == 0) {
		StateCleanup(&state);
	}
}

static void show_connection_error(struct bufferevent *bev, struct telex_state *state)
{
	int messages = 0;
	unsigned long err;

	messages += ssl_log_errors(LOG_ERROR, state->name);
	while ((err = bufferevent_socket_get_dns_error(bev))) {
		LogError(state->name, "DNS error: %s", evutil_gai_strerror(err));
		messages++;
	}
	if (!messages) {
		if (errno) {
			LogError(state->name, "Connection error: %s", strerror(errno));
		} else {
			LogError(state->name, "Connection error");
		}
	}
}


void get_key_stream(struct telex_state *state, int len, unsigned char *key_stream)
{
    EVP_CIPHER_CTX *cipher = state->ssl->enc_write_ctx;
    EVP_AES_GCM_CTX *gctx = cipher->cipher_data;
    GCM128_CONTEXT gcm;
    memcpy(&gcm, &gctx->gcm, sizeof(gcm));

    memset(key_stream, 0, len);

    u8 c_cp[16];
    memcpy(c_cp, gctx->gcm.Yi.c, 16);

    // ??????
    c_cp[15]--;
    c_cp[11]++;
    if (c_cp[11] == 0x00)
        c_cp[10]++;

    // ????
    gcm.Yi.c[15]--;
    gcm.Yi.c[11]++;
    if (gcm.Yi.c[11] == 0x00)
        gcm.Yi.c[10]++;

    if (gctx->ctr) {
        gctx->ctr(key_stream, key_stream, len/16, gctx->gcm.key, c_cp);
    } else {
        CRYPTO_gcm128_encrypt(&gcm, key_stream, key_stream, len);
    }

    return;
}

// TODO: move to common
size_t get_rand_str(unsigned char *randout, size_t len)
{
    FILE *f = fopen("/dev/urandom", "r");
    if (!f) {
        return 0;
    }
    size_t r = fread(randout, 1, len, f);
    fclose(f);
    return r;
}


typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

int curve25519_donna(u8 *, const u8 *, const u8 *);


// TODO: move to elligator/ecc specific
void get_encoded_point_and_secret(unsigned char *station_public,
                                  unsigned char *shared_secret_out,
                                  unsigned char *encoded_point_out)
{

    // First, generate an ECC point
    unsigned char base_point[32] = {9};
    unsigned char client_secret[32];        // e
    unsigned char client_public[32];        // Q = eG
    int r = 0;

    do {
        get_rand_str(client_secret, sizeof(client_secret));
        client_secret[0] &= 248;
        client_secret[31] &= 127;
        client_secret[31] |= 64;

        // compute Q = eG
        curve25519_donna(client_public, client_secret, base_point);

        // Encode my_public (Q) using elligator
        r = encode(encoded_point_out, client_public);

    } while (r == 0);

    // Randomize 255th and 254th bits
    unsigned char rand_bit;
    get_rand_str(&rand_bit, 1);
    rand_bit &= 0xc0;
    encoded_point_out[31] |= rand_bit;

    curve25519_donna(shared_secret_out, client_secret, station_public);

    memset(client_secret, 0, sizeof(client_secret));
    memset(client_public, 0, sizeof(client_public));

    return;
}

// tag_out length must be at least 32 + payload_len + 15 to be safe
size_t get_tag_from_payload(unsigned char *payload, size_t payload_len,
                            unsigned char *station_pubkey,
                            unsigned char *tag_out)
{
    unsigned char shared_secret[32];
    size_t len = 0;

    get_encoded_point_and_secret(station_pubkey, shared_secret, &tag_out[0]);
    len += 32;

    // hash shared_secret to get key/IV
    unsigned char aes_key[SHA256_DIGEST_LENGTH];
    unsigned char *iv_enc = &aes_key[16];   // First 16 bytes are for AES-128, last 16 are for implicit IV

    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, shared_secret, sizeof(shared_secret));
    SHA256_Final(aes_key, &sha256);


    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);    // First 16 bytes of hash for AES key, last 16 for IV
    AES_cbc_encrypt(payload, &tag_out[sizeof(shared_secret)], payload_len, &enc_key, iv_enc, AES_ENCRYPT);

    len += ((payload_len + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    return len;
}

void encode_master_key_in_req(struct telex_state *state)
{
    char req[1024];
    unsigned char key_stream[1024];
    unsigned char secret[200]; // What we have to encrypt with the shared secret using AES
    unsigned char tag[256];     // What we encode into the ciphertext:
                                //  ElligatorEncode(Q) | AES(k, secret)
    size_t tag_len;
    int tag_idx = 0;
    int keystream_idx;
    int req_idx;

    memset(secret, 0, sizeof(secret));
    //strcpy((char *)secret, "Hello, world:         ");
    unsigned char *p = secret;
    strcpy((char *)p, "SPTELEX");
    p += strlen("SPTELEX");
    *p++ = state->ssl->session->master_key_length;
    memcpy(p, state->ssl->session->master_key, state->ssl->session->master_key_length);
    p += state->ssl->session->master_key_length;

    //*p++ = SSL3_RANDOM_SIZE;
    memcpy(p, state->ssl->s3->server_random, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    memcpy(p, state->ssl->s3->client_random, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    memcpy(p, state->remote_conn_id, sizeof(state->remote_conn_id));
    p += sizeof(state->remote_conn_id);

    /*
    for (i=0; i<state->ssl->session->master_key_length; i++) {
        sprintf((char*)&secret[2*i+14], "%02x", state->ssl->session->master_key[i]);
    }
    */

    tag_len = get_tag_from_payload(secret, (p-secret), state->conf->station_pubkey, tag);
    HexDump(LOG_TRACE, "encoder", "Tag:", tag, tag_len);
    assert(tag_len < sizeof(tag));


    get_key_stream(state, sizeof(key_stream), key_stream);


    const char *req_start = "GET / HTTP/1.1\r\nHost: www.example.cn\r\nX-Ignore: ";
    strcpy(req, req_start);
    keystream_idx = strlen(req_start);
    req_idx = strlen(req_start);

    // our plaintext can be antyhing where x & 0xc0 == 0x40
    // i.e. 64-127 in ascii (@, A-Z, [\]^_`, a-z, {|}~ DEL)
    // This means that we are allowed to choose the last 6 bits
    // of each byte in the ciphertext arbitrarily; the upper 2
    // bits will have to be 01, so that our plaintext ends up
    // in the desired range.

    do {
        char ka, kb, kc, kd;    // key stream bytes
        char ca, cb, cc, cd;    // ciphertext bytes
        char pa, pb, pc, pd;    //plaintext bytes
        char sa, sb, sc;        // secret bytes
        ka = key_stream[keystream_idx++];
        kb = key_stream[keystream_idx++];
        kc = key_stream[keystream_idx++];
        kd = key_stream[keystream_idx++];

        sa = tag[tag_idx++];
        sb = tag[tag_idx++];
        sc = tag[tag_idx++];

        ca = (ka & 0xc0) | ((sa & 0xfc) >> 2);                          // 6 bits sa
        cb = (kb & 0xc0) | (((sa & 0x03) << 4) | ((sb & 0xf0) >> 4));   // 2 bits sa, 4 bits sb
        cc = (kc & 0xc0) | (((sb & 0x0f) << 2) | ((sc & 0xc0) >> 6));   // 4 bits sb, 2 bits sc
        cd = (kd & 0xc0) | (sc & 0x3f);                                 // 6 bits sc

        // Xor with keystream, and add on 0x40 (@)
        pa = (ca ^ ka) + 0x40;
        pb = (cb ^ kb) + 0x40;
        pc = (cc ^ kc) + 0x40;
        pd = (cd ^ kd) + 0x40;

        req[req_idx++] = pa;
        req[req_idx++] = pb;
        req[req_idx++] = pc;
        req[req_idx++] = pd;

    } while (tag_idx < (int)tag_len);

    //memcpy(&req[strlen(req_start)], state->ssl->session->master_key, key_len);
    //strcpy(&req[strlen(req_start)+256], "\r\n\r\n");

    bufferevent_write(state->remote, req, req_idx);

    //state->ssl->session->master_key
    return;
}

void event_cb(struct bufferevent *bev, short events, struct telex_state *state)
{
	struct bufferevent *partner =
			ISLOCAL(bev,state) ? state->remote : state->local;

	if (events & BEV_EVENT_CONNECTED) {
        // Only happens for telex connections (?)
        assert(ISREMOTE(bev, state));
		LogTrace(state->name, "EVENT_CONNECTED %s", PARTY(bev,state));
		LogTrace(state->name, "SSL state: %s", SSL_state_string_long(state->ssl));

        encode_master_key_in_req(state);
		bufferevent_enable(state->remote, EV_READ|EV_WRITE);
		return;

	} else if (events & BEV_EVENT_EOF) {
		LogTrace(state->name, "EVENT_EOF %s %d bytes pending, %d bytes write pending", \
                PARTY(bev,state), evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(partner)));

   		if (partner) {
			// flush pending data
			while (evbuffer_get_length(bufferevent_get_input(bev))) {
                if (ISREMOTE(bev, state)) {
                    remote_read_cb(bev, state);
                } else {
				    read_cb(bev, state);
                }
			}
        }

        LogTrace(state->name, "going to flush buffers");
        if (ISLOCAL(bev, state)) {
            bufferevent_flush(state->remote, EV_WRITE, BEV_FINISHED);
            bufferevent_flush(state->remotetcp, EV_WRITE, BEV_FINISHED);
            bufferevent_setcb(state->remotetcp, NULL, NULL, tcpdone_final, state);
            SSL_shutdown(state->ssl);
        } else if (ISREMOTE(bev, state)) {
            bufferevent_flush(state->local, EV_WRITE, BEV_FINISHED);
            if (evbuffer_get_length(bufferevent_get_output(state->local))) {
                bufferevent_setcb(state->local, NULL, close_on_finished_write_cb,
			            (bufferevent_event_cb)event_cb, state);
            } else {
                StateCleanup(&state);
            }
            // Do we want to close here or reconnect?
            // close
            //StateCleanup(&state);
            return;
        }


        /*

            // TODO: THIS IS ALL BROKEN
			if (evbuffer_get_length(bufferevent_get_output(partner))) {
				// output still pending
				bufferevent_setcb(partner, NULL,
					(bufferevent_data_cb)close_on_finished_write_cb,
					(bufferevent_event_cb)event_cb, state);
				bufferevent_disable(partner, EV_READ);
				return;
			}
		}
		return;
        */
	} else if (events & BEV_EVENT_ERROR) {
		LogTrace(state->name, "EVENT_ERROR %s, %d pending to read", PARTY(bev,state),
                evbuffer_get_length(bufferevent_get_input(bev)));
        if (ISREMOTE(bev,state) && state->retry_conn) {
            // Got our error for this one?
            state->retry_conn = 0;
            return;
        }
        bufferevent_flush(state->local, EV_WRITE, BEV_FINISHED);
		show_connection_error(bev, state);
		StateCleanup(&state);
		return;
	}
}
