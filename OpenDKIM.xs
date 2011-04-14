#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <opendkim/dkim.h>

/* h2xs -A -n Mail::OpenDKIM */

static SV *dns_callback = (SV *)NULL;
static SV *final_callback = (SV *)NULL;


/*
 * called when the OpenDKIMlibrary wants to call the callback function provided to
 * dkim_set_dns_callback
 */
static void
call_dns_callback(const void *context)
{
	dSP;
	SV *sv = dns_callback;

	if(sv == NULL) {
		croak("Internal error: call_dns_callback called, but nothing to call");
		return;
	}

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(context, 0)));
	PUTBACK;

	call_sv(dns_callback, G_DISCARD);
}

/*
 * called when the OpenDKIMlibrary wants to call the callback function provided to
 * dkim_set_final
 */
static DKIM_CBSTAT
call_final_callback(DKIM *dkim, DKIM_SIGINFO **sigs, int nsigs)
{
	dSP;
	int count, status;
	SV *sv = final_callback;

	if(sv == NULL) {
		croak("Internal error: call_final_callback called, but nothing to call");
		return;
	}

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv((void *)dkim, 0)));
	XPUSHs(sv_2mortal(newSVpv((void *)sigs, 0)));
	XPUSHs(sv_2mortal(newSViv(nsigs)));
	PUTBACK;

	call_sv(final_callback, G_SCALAR);

	SPAGAIN;

	if(count != 1) {
		croak("Internal error: final_callback routine returned %d items, 1 was expected",
			count);
		return;
	}

	status = POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return status;
}

MODULE = Mail::OpenDKIM		PACKAGE = Mail::OpenDKIM
PROTOTYPES: DISABLE

unsigned long
dkim_ssl_version()
	CODE:
		RETVAL = dkim_ssl_version();
	OUTPUT:
		RETVAL

unsigned long
dkim_libversion()
	CODE:
		RETVAL = dkim_libversion();
	OUTPUT:
		RETVAL

DKIM_LIB *
_dkim_init()
	CODE:
		RETVAL = dkim_init(NULL, NULL);
	OUTPUT:
		RETVAL

void
_dkim_close(d)
		DKIM_LIB *d
	CODE:
		dkim_close(d);

_Bool
_dkim_libfeature(d, fc)
		DKIM_LIB *d
		unsigned int fc
	CODE:
		RETVAL = dkim_libfeature(d, fc);
	OUTPUT:
		RETVAL

int
_dkim_flush_cache(d)
		DKIM_LIB *d
	CODE:
		RETVAL = dkim_flush_cache(d);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_getcachestats(queries, hits, expired)
		unsigned int queries = NO_INIT
		unsigned int hits = NO_INIT
		unsigned int expired = NO_INIT
	CODE:
		RETVAL = dkim_getcachestats(&queries, &hits, &expired);
	OUTPUT:
		queries
		hits
		expired
		RETVAL

DKIM *
_dkim_sign(libhandle, id, secretkey, selector, domain, hdrcanon_alg, bodycanon_alg, sign_alg, length, statp)
		DKIM_LIB *libhandle
		const char *id
		const char *secretkey
		const char *selector
		const char *domain
		dkim_canon_t hdrcanon_alg
		dkim_canon_t bodycanon_alg
		dkim_alg_t sign_alg
		off_t length
		DKIM_STAT statp = NO_INIT
	CODE:
		RETVAL = dkim_sign(libhandle, (const unsigned char *)id, NULL, (dkim_sigkey_t)secretkey, (const unsigned char *)selector, (const unsigned char *)domain, hdrcanon_alg, bodycanon_alg, sign_alg, length, &statp);
	OUTPUT:
		RETVAL
		statp

DKIM_STAT
_dkim_set_dns_callback(libopendkim, func, interval)
		DKIM_LIB *libopendkim
		SV *func
		unsigned int interval
	CODE:
		if(dns_callback == (SV *)NULL)
			dns_callback = newSVsv(func);
		else
			SvSetSV(dns_callback, func);

		RETVAL = dkim_set_dns_callback(libopendkim, call_dns_callback, interval);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_set_final(libopendkim, func)
		DKIM_LIB *libopendkim
		SV *func
	CODE:
		if(final_callback == (SV *)NULL)
			final_callback = newSVsv(func);
		else
			SVSetSV(final_callback, func);

		RETVAL = dkim_set_final(libopendkim, call_final_callback);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_free(d)
		DKIM *d
	CODE:
		RETVAL = dkim_free(d);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_header(dkim, header, len)
		DKIM *dkim
		unsigned char *header
		size_t len
	CODE:
		RETVAL = dkim_header(dkim, header, len);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_eoh(dkim)
		DKIM *dkim
	CODE:
		RETVAL = dkim_eoh(dkim);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_chunk(dkim, chunkp, len)
		DKIM *dkim
		unsigned char *chunkp
		size_t len
	CODE:
		RETVAL = dkim_chunk(dkim, chunkp, len);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_eom(dkim)
		DKIM *dkim
	CODE:
		RETVAL = dkim_eom(dkim, NULL);
	OUTPUT:
		RETVAL

char *
_dkim_get_signer(dkim)
		DKIM *dkim
	CODE:
		RETVAL = dkim_get_signer(dkim);
	OUTPUT:
		RETVAL

const void *
_dkim_get_user_context(dkim)
		DKIM *dkim
	CODE:
		RETVAL = dkim_get_user_context(dkim);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_getsighdr_d(dkim, initial, buf, len)
		DKIM *dkim
		size_t initial
		unsigned char *buf = NO_INIT
		size_t len = NO_INIT
	CODE:
		RETVAL = dkim_getsighdr_d(dkim, initial, &buf, &len);
	OUTPUT:
		buf
		len
		RETVAL

const char *
_dkim_geterror(dkim)
		DKIM *dkim
	CODE:
		RETVAL = dkim_geterror(dkim);
	OUTPUT:
		RETVAL
