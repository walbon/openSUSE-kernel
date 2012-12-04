#include <linux/linkage.h>

	.section ".init.data","aw"

	.globl modsign_certificate_list
modsign_certificate_list:
	.incbin "signing_key.x509"
	.incbin "extra_certificates"
	.globl modsign_certificate_list_end
modsign_certificate_list_end:
