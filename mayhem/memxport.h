/* In-memory DIS transport: the harness plays the socket peer, the PKTV1 framing and DIS decoders are the real ones. */
#ifndef MEMXPORT_H
#define MEMXPORT_H
#include <pbs_config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "dis.h"

#define MX_FD 100

static const unsigned char *mx_in;
static size_t mx_inlen, mx_inpos;
static unsigned char *mx_out;
static size_t mx_outlen, mx_outcap;
static pbs_tcp_chan_t *mx_chan;

static pbs_tcp_chan_t *
mx_get_chan(int fd)
{
	(void) fd;
	return mx_chan;
}

static int
mx_set_chan(int fd, pbs_tcp_chan_t *chan)
{
	(void) fd;
	mx_chan = chan;
	return 0;
}

static int
mx_recv(int fd, void *data, int len)
{
	(void) fd;
	if (len < 0 || (size_t) len > mx_inlen - mx_inpos) {
		mx_inpos = mx_inlen;
		return -2;
	}
	memcpy(data, mx_in + mx_inpos, (size_t) len);
	mx_inpos += (size_t) len;
	return len;
}

static int
mx_send(int fd, void *data, int len)
{
	(void) fd;
	if (mx_outlen + (size_t) len > mx_outcap) {
		mx_outcap = (mx_outlen + (size_t) len) * 2;
		mx_out = (unsigned char *) realloc(mx_out, mx_outcap);
	}
	memcpy(mx_out + mx_outlen, data, (size_t) len);
	mx_outlen += (size_t) len;
	return len;
}

/* Attach a fresh channel whose read side serves in[0..n). Bytes written with dis_puts/dis_flush land in mx_out. */
static void
mx_open(const unsigned char *in, size_t n)
{
	pfn_transport_get_chan = mx_get_chan;
	pfn_transport_set_chan = mx_set_chan;
	pfn_transport_recv = mx_recv;
	pfn_transport_send = mx_send;
	mx_in = in;
	mx_inlen = n;
	mx_inpos = 0;
	mx_outlen = 0;
	mx_chan = NULL;
	errno = 0;
	dis_setup_chan(MX_FD, mx_get_chan);
}

static void
mx_close(void)
{
	dis_destroy_chan(MX_FD);
	mx_chan = NULL;
}
#endif
