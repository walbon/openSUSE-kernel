#include <linux/linkage.h>

	.section ".init.data","aw"

GLOBAL(modsign_certificate_list)
	.incbin "signing_key.x509"
	.incbin "extra_certificates"
END(modsign_certificate_list)
GLOBAL(modsign_certificate_list_end)
