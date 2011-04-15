#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <opendkim/dkim.h>

/* h2xs -A -n Mail::OpenDKIM */

/* callbacks */
static SV *dns_callback = (SV *)NULL;
static SV *final_callback = (SV *)NULL;
static SV *key_lookup_callback = (SV *)NULL;
static SV *policy_lookup_callback = (SV *)NULL;

/*
 * dkim.h doesn't specify the contents of the DKIM and DKIM_SIGINFO structures, it just
 * declares them :-(
 * So this is an overkill size, that SHOULD be large enough.  See dkim-types.h for more
 * information about the structures
 */

#define	SIZEOF_DKIM		4096
#define	SIZEOF_DKIM_SIGINFO	1024

/*
 * These routines allow us to call callbacks that are written in and supplied using Perl that
 * are maintained and called from within the OpenDKIM library
 *
 * e.g.
 * sub dns_callback {
 *  my $context = shift;
 *
 *   print "DNS called back with context $context\n";
 * }
 *
 * set_dns_callback({ function => \&callback, interval => 1 });
 *
 * These are all dummy callbacks that we pass to OpenDKIM, and when OpenDKIM calls them they
 * call the Perl routines supplied by the caller
 */

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
		return DKIM_CBSTAT_ERROR;
	}

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv((void *)dkim, SIZEOF_DKIM)));
	XPUSHs(sv_2mortal(newSVpv((void *)sigs, nsigs * SIZEOF_DKIM_SIGINFO)));
	XPUSHs(sv_2mortal(newSViv(nsigs)));
	PUTBACK;

	count = call_sv(final_callback, G_SCALAR);

	SPAGAIN;

	if(count != 1) {
		croak("Internal error: final_callback routine returned %d items, 1 was expected",
			count);
		return DKIM_CBSTAT_ERROR;
	}

	status = POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return status;
}

/*
 * called when the OpenDKIMlibrary wants to call the callback function provided to
 * dkim_set_key_lookup
 */
static DKIM_CBSTAT
call_key_lookup_callback(DKIM *dkim, DKIM_SIGINFO *siginfo, unsigned char *buf, size_t buflen)
{
	dSP;
	int count, status;
	SV *sv = key_lookup_callback;

	if(sv == NULL) {
		croak("Internal error: call_key_lookup_callback called, but nothing to call");
		return DKIM_CBSTAT_ERROR;
	}

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv((void *)dkim, SIZEOF_DKIM)));
	XPUSHs(sv_2mortal(newSVpv((void *)siginfo, SIZEOF_DKIM_SIGINFO)));
	XPUSHs(sv_2mortal(newSVpv((void *)buf, buflen + 1)));
	XPUSHs(sv_2mortal(newSViv(buflen)));
	PUTBACK;

	count = call_sv(key_lookup_callback, G_SCALAR);

	SPAGAIN;

	if(count != 1) {
		croak("Internal error: key_lookup_callback routine returned %d items, 1 was expected",
			count);
		return DKIM_CBSTAT_ERROR;
	}

	status = POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return status;
}

/*
 * called when the OpenDKIMlibrary wants to call the callback function provided to
 * dkim_set_policy_lookup
 */
static DKIM_CBSTAT
call_policy_lookup_callback(DKIM *dkim, unsigned char *query, _Bool excheck, unsigned char *buf, size_t buflen, int *qstat)
{
	dSP;
	int count, status;
	SV *sv = policy_lookup_callback;

	if(sv == NULL) {
		croak("Internal error: call_policy_lookup_callback called, but nothing to call");
		return DKIM_CBSTAT_ERROR;
	}

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv((void *)dkim, SIZEOF_DKIM)));
	XPUSHs(sv_2mortal(newSVpv((void *)query, 0)));
	XPUSHs(sv_2mortal(newSViv(excheck)));
	XPUSHs(sv_2mortal(newSVpv((void *)buf, buflen + 1)));
	XPUSHs(sv_2mortal(newSViv(buflen)));
	XPUSHs(sv_2mortal(newSVpv((void *)qstat, sizeof(int))));
	PUTBACK;

	count = call_sv(policy_lookup_callback, G_SCALAR);

	SPAGAIN;

	if(count != 1) {
		croak("Internal error: policy_lookup_callback routine returned %d items, 1 was expected",
			count);
		return DKIM_CBSTAT_ERROR;
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
			SvSetSV(final_callback, func);

		RETVAL = dkim_set_final(libopendkim, call_final_callback);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_set_key_lookup(libopendkim, func)
		DKIM_LIB *libopendkim
		SV *func
	CODE:
		if(key_lookup_callback == (SV *)NULL)
			key_lookup_callback = newSVsv(func);
		else
			SvSetSV(key_lookup_callback, func);

		RETVAL = dkim_set_key_lookup(libopendkim, call_key_lookup_callback);
	OUTPUT:
		RETVAL

DKIM_STAT
_dkim_set_policy_lookup(libopendkim, func)
		DKIM_LIB *libopendkim
		SV *func
	CODE:
		if(policy_lookup_callback == (SV *)NULL)
			policy_lookup_callback = newSVsv(func);
		else
			SvSetSV(policy_lookup_callback, func);

		RETVAL = dkim_set_policy_lookup(libopendkim, call_policy_lookup_callback);
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

unsigned char *
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
