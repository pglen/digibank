/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "TAP-0310"
 * 	found in "../tap3.asn1"
 * 	`asn1c -S ../../skeletons`
 */

#ifndef	_NonChargedParty_H_
#define	_NonChargedParty_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AddressStringDigits.h"
#include "CalledNumAnalysisCode.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NonChargedParty */
typedef struct NonChargedParty {
	AddressStringDigits_t	*nonChargedNumber	/* OPTIONAL */;
	CalledNumAnalysisCode_t	*calledNumAnalysisCode	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NonChargedParty_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NonChargedParty;

#ifdef __cplusplus
}
#endif

#endif	/* _NonChargedParty_H_ */
#include <asn_internal.h>
