#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <opendkim/dkim.h>

/* h2xs -A -n Mail::OpenDKIM::DKIM */

MODULE = Mail::OpenDKIM::DKIM		PACKAGE = Mail::OpenDKIM::DKIM
PROTOTYPES: DISABLE

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
