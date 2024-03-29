#ifndef __GLOBAL_H_
#define __GLOBAL_H_

#include <stdint.h>
#include <sys/types.h>

#include <moepcommon/util.h>

#define DEFAULT_MTU			1500
#define DEFAULT_MTU_OFFSET		512
//#define DEFAULT_LINK_QUALITY		0.9
#define DEFAULT_BEACON_INTERVAL		100

#define MEMORY_ALIGNMENT		32
#define GENERATION_MIN_PACKET_SIZE	256
#define GENERATION_MAX_PDU_SIZE		8192
#define GENERATION_MAX_CODED_SIZE	GENERATION_MAX_PDU_SIZE - 7
#define GENERATION_MAX_SEQUENCE_NUMBER		UINT16_MAX

#define GENERATION_RTX_MAX_TIMEOUT	20
#define GENERATION_RTX_MIN_TIMEOUT	5

#define GENERATION_MAX_WINDOW		32
#define GENERATION_WINDOW		8
#define GENERATION_MAX_SIZE		254
// TODO GENERATION_SIZE was previously defined for bidirectional session
//  thus having 64 frames in each direction. One might want to half the
//  macro when using the new bidirectional sessions.
#define GENERATION_SIZE			128

#define QDELAY_UPDATE_WEIGHT		0.5
//#define WMEWMA_WEIGHT			0.9
#define RALQE_TAU			0.05
#define RALQE_THETA			0.98
#define RALQE_MAX			5000

#define SESSION_ACK_TIMEOUT	    1
#define SESSION_TIMEOUT			30000

#define SESSION_LOG_FILE_PREFIX		"/dev/shm/ncm_session_"


#define BIT(x) (1ULL << (x))




//FIXME
#define MOEPGF				MOEPGF256

#define GENERATION_FBLEN		1+2+2
#define NCM_HDRLEN_CODED		2+13+1+2+2
#define NCM_COEFFLEN			GENERATION_SIZE/(8/(8 >> (3-MOEPGF)))
#define NCM_HDRLEN_CODED_TOTAL		NCM_HDRLEN_CODED + GENERATION_FBLEN * GENERATION_WINDOW + NCM_COEFFLEN

#endif
