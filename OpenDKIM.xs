#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <opendkim/dkim.h>

/* h2xs -A -n Mail::OpenDKIM */

MODULE = Mail::OpenDKIM		PACKAGE = Mail::OpenDKIM		
PROTOTYPES: DISABLE

BOOT:
boot_Mail__OpenDKIM__DKIM(aTHX_ cv);

unsigned long
dkim_ssl_version()
	CODE:
		RETVAL = dkim_ssl_version();
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

int
_dkim_flush_cache(d)
		DKIM_LIB *d
	CODE:
		RETVAL = dkim_flush_cache(d);
	OUTPUT:
		RETVAL
