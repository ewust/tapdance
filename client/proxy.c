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

void first_read_cb(struct bufferevent *bev, struct telex_state *state);
static void read_cb(struct bufferevent *, struct telex_state *);
void remote_read_cb(struct bufferevent *bev, struct telex_state *state);
static void event_cb(struct bufferevent *, short, struct telex_state *);
static void drained_write_cb(struct bufferevent *, struct telex_state *);
static void close_on_finished_write_cb(struct bufferevent *, struct telex_state *);

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

    HexDump(LOG_TRACE, state->name, "Opening telex id ", state->remote_conn_id, sizeof(state->remote_conn_id));
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

	state->remotetcp = bufferevent_socket_new(state->base, -1,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if (!state->remotetcp) {
		LogError(state->name, "Could not create remote bufferevent socket");
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

    if (msg.type != MSG_INIT || msg.magic_val != SPTELEX_MAGIC_VAL) {
        // Not Telex, end this connection
        LogWarn(state->name, "Failed to get a SPTelex init msg (not using a Telex server, or it's not running?) Got: %04x", msg.magic_val);
        StateCleanup(&state);
        return;
    }

    LogTrace(state->name, "Got SPTelex init");
    state->max_send = msg.win_size;

    // Set up to start passing between proxy and client
	bufferevent_setcb(state->remote, (bufferevent_data_cb)remote_read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);

    // Allow local proxy to start sending data
	bufferevent_enable(state->local,  EV_READ|EV_WRITE);
}

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
    size_t buffer_len = evbuffer_get_length(src);

    if (buffer_len < sizeof(msg_type)) {
        return;
    }

    evbuffer_copyout(src, &msg_type, sizeof(msg_type));

    switch (msg_type) {
    case MSG_DATA:
        // Read message length from header
        if ((buffer_len - sizeof(msg_type)) < sizeof(msg_len)) {
            return;
        }
        evbuffer_copyout(src, &msg_len, sizeof(msg_len));
        msg_len = ntohs(msg_len);
        if ((buffer_len - sizeof(msg_type) - sizeof(msg_len)) < msg_len) {
            return;
        }
        // Eat header
        evbuffer_drain(src, sizeof(msg_type) + sizeof(msg_len));

        // Book keeping
		state->in_remote += msg_len;
        LogTrace(state->name, "READCB remote: MSG_DATA (got %lu bytes / %lu bytes so far)",
                msg_len, state->in_remote);

        evbuffer_remove_buffer(src, bufferevent_get_output(state->local), msg_len);
        return;

    case MSG_RECONNECT:
        LogTrace(state->name, "READCB remote: MSG_RECONNECT");
        state->retry_conn = 1;
        bufferevent_disable(state->local, EV_READ);
        cleanup_ssl(state);
        make_new_telex_conn(state);
        return;

    case MSG_CLOSE:
        LogTrace(state->name, "READCB remote: MSG_CLOSE");
        state->retry_conn = 0;
        StateCleanup(&state);
        return;

    default:
        LogError(state->name, "Got invalid MSG_TYPE=%02x", msg_type);
        return;
    }

}

void read_cb(struct bufferevent *bev, struct telex_state *state)
{
	struct bufferevent *partner =
			ISLOCAL(bev,state) ? state->remote : state->local;

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	size_t total = 0;
	if (ISLOCAL(bev,state)) {
        if ((state->in_local + len) > state->max_send) {
            LogDebug(state->name, "about to exceed send window; starting new connection");
            cleanup_ssl(state);
            make_new_telex_conn(state);
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

void close_on_finished_write_cb(struct bufferevent *bev, struct telex_state *state)
{
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

void encode_master_key_in_req(struct telex_state *state)
{
    char req[1024];
    unsigned char key_stream[1024];
    unsigned char secret[200]; // = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    int secret_len = 200;
    int secret_idx = 0;
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

        sa = secret[secret_idx++];
        sb = secret[secret_idx++];
        sc = secret[secret_idx++];

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

    } while (secret_idx < secret_len);

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
        bufferevent_enable(state->local, EV_READ|EV_WRITE);
		bufferevent_enable(state->remote, EV_READ|EV_WRITE);
		return;

	} else if (events & BEV_EVENT_EOF) {
		LogTrace(state->name, "EVENT_EOF %s", PARTY(bev,state));
		if (partner) {
			// flush pending data
			if (evbuffer_get_length(bufferevent_get_input(bev))) {
				read_cb(bev, state);
			}

			if (evbuffer_get_length(bufferevent_get_output(partner))) {
				// output still pending
				bufferevent_setcb(partner, NULL,
					(bufferevent_data_cb)close_on_finished_write_cb,
					(bufferevent_event_cb)event_cb, state);
				bufferevent_disable(partner, EV_READ);
				return;
			}
		}
		StateCleanup(&state);
		return;

	} else if (events & BEV_EVENT_ERROR) {
		LogTrace(state->name, "EVENT_ERROR %s", PARTY(bev,state));
        if (ISREMOTE(bev,state) && state->retry_conn) {
            // Got our error for this one?
            state->retry_conn = 0;
            return;
        }
		show_connection_error(bev, state);
		StateCleanup(&state);
		return;
	}
}
