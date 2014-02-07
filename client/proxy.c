#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <assert.h>
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

static void read_cb(struct bufferevent *, struct telex_state *);
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

	LogInfo(state->name, "Opened (%u active)", state->conf->count_open_tunnels);
	return state;
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

    char portbuf[10];
    struct evutil_addrinfo hint;

    evutil_snprintf(portbuf, sizeof(portbuf), "%d", conf->notblocked_port);

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_socktype = SOCK_STREAM; 

    // TODO: check return, _inc(???) 
    LogTrace(state->name, "Resolving %s", conf->notblocked_host);

    // TODO: make nonblocking..
    bufferevent_socket_connect_hostname(state->remotetcp, NULL, AF_INET, conf->notblocked_host, conf->notblocked_port);
    /*
    evutil_getaddrinfo_async(conf->dns_base, conf->notblocked_host,
                portbuf, &hint, proxy_notblocked_getaddrinfo_cb, state);
    */



    // After resolution...
    /*
    struct sockaddr_in sin;
    if (getpeername(bufferevent_getfd(state->remotetcp), (struct sockaddr *)&sin, (socklen_t*)sizeof(sin)) < 0) {
        perror("getpeername");
        LogError("proxy", "getpeername failed");
        StateCleanup(&state);
        return;
    }
    */

	if (ssl_new_telex(state) < 0) {
		ssl_log_errors(LOG_ERROR, state->name);
		LogError(state->name, "Could not create new telex SSL connection object");
		StateCleanup(&state);
		return;
	}
	_inc(SSL);

    /*
    char ip_p[INET_ADDRSTRLEN];
    LogTrace(state->name, "Connecting to %s:%d",
             evutil_inet_ntop(AF_INET, server_ip, ip_p, sizeof(ip_p)), state->conf->notblocked_port);
    //bufferevent_socket_connect(state->remotetcp, ai->ai_addr, (int)ai->ai_addrlen);
    */

	state->remote = bufferevent_openssl_filter_new(state->base, state->remotetcp,
		state->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
		// Not BEV_OPT_CLOSE_ON_FREE!
	if (!state->remote) {
		LogError(state->name, "Could not create remote SSL bufferevent filter");
		StateCleanup(&state);
		return;
	}
	_inc(BEV);

	bufferevent_setcb(state->remote, (bufferevent_data_cb)read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);
	bufferevent_setcb(state->local, (bufferevent_data_cb)read_cb, NULL,
		(bufferevent_event_cb)event_cb, state);
}

#define ISLOCAL(bev, state) ((bev) == (state)->local)
#define ISREMOTE(bev, state) ((bev) == (state)->remote)
#define PARTY(bev, state) (ISLOCAL((bev),(state)) ? "local" : \
	(ISREMOTE((bev),(state)) ? "remote" : "other" ))

void read_cb(struct bufferevent *bev, struct telex_state *state)
{
	struct bufferevent *partner = 
			ISLOCAL(bev,state) ? state->remote : state->local;		

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	size_t total = 0;
	if (ISLOCAL(bev,state)) {
		total = (state->in_local += len);
	} else if (ISREMOTE(bev,state)) {
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
    int i;
    //int key_len = state->ssl->session->master_key_length;
    EVP_CIPHER_CTX *cipher = state->ssl->enc_write_ctx;
    EVP_AES_GCM_CTX *gctx = cipher->cipher_data;

    memset(key_stream, 0, len);

    printf("%p and %d byte ivlen Yi.c: ", gctx->ctr, gctx->ivlen);

    for (i=0; i<16; i++) {
        printf("%02x", gctx->gcm.Yi.c[i]);
    }
    printf("\n");
    printf("read Yi.c: ");
    for (i=0; i<16; i++) {
        printf("%02x", ((EVP_AES_GCM_CTX*)state->ssl->enc_read_ctx->cipher_data)->gcm.Yi.c[i]);
    }
    printf("\n");
    printf("iv: ");
    for (i=0; i<12; i++) {
        printf("%02x", gctx->iv[i]);
    }
    printf("\n");

    u8 c_cp[16];
    memcpy(c_cp, gctx->gcm.Yi.c, 16);

    // ??????
    c_cp[15]--;
    c_cp[11]++;
    if (c_cp[11] == 0x00)
        c_cp[10]++;

    gctx->ctr(key_stream, key_stream, len/16, gctx->gcm.key, c_cp);
    printf("key: ");
    for (i=0; i<16; i++) {
        printf("%02x", ((unsigned char*)gctx->gcm.key)[i]);
    }
    printf("\n");

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
    int i;
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

    printf("=========\n");
    printf("%s\n", req);

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
		LogTrace(state->name, "EVENT_CONNECTED %s", PARTY(bev,state));
		LogTrace(state->name, "SSL state: %s", SSL_state_string_long(state->ssl));
        int i;
        printf("\n");
        for (i=0; i< state->ssl->session->master_key_length; i++) {
            printf("%02x", state->ssl->session->master_key[i]);
        }
        printf("\n");
        encode_master_key_in_req(state);
		bufferevent_enable(state->local,  EV_READ|EV_WRITE);
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
		show_connection_error(bev, state);
		StateCleanup(&state);
		return;
	}
}
