/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copyright (c) 2012, Intel Corporation
;
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are
; met:
;
; * Redistributions of source code must retain the above copyright
;   notice, this list of conditions and the following disclaimer.
;
; * Redistributions in binary form must reproduce the above copyright
;   notice, this list of conditions and the following disclaimer in the
;   documentation and/or other materials provided with the
;   distribution.
;
; * Neither the name of the Intel Corporation nor the names of its
;   contributors may be used to endorse or promote products derived from
;   this software without specific prior written permission.
;
;
; THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
; EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
; PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
; CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
; PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This code schedules 1 blocks at a time, with 4 lanes per block
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
*/
/*
 * Conversion to GAS assembly and integration to libgcrypt
 *  by Jussi Kivilinna <jussi.kivilinna@iki.fi>
 */

#ifdef __x86_64
#include <config.h>
#if (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
     defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)) && \
    defined(HAVE_INTEL_SYNTAX_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_AVX2) && defined(HAVE_GCC_INLINE_ASM_BMI2) && \
    defined(USE_SHA512)

#ifdef __PIC__
#  define ADD_RIP +rip
#else
#  define ADD_RIP
#endif

#ifdef HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS
# define ELF(...) __VA_ARGS__
#else
# define ELF(...) /*_*/
#endif

.intel_syntax noprefix

.text

/* Virtual Registers */
Y_0 = ymm4
Y_1 = ymm5
Y_2 = ymm6
Y_3 = ymm7

YTMP0 = ymm0
YTMP1 = ymm1
YTMP2 = ymm2
YTMP3 = ymm3
YTMP4 = ymm8
XFER =  YTMP0

BYTE_FLIP_MASK =  ymm9

INP =         rdi /* 1st arg */
CTX =         rsi /* 2nd arg */
NUM_BLKS =    rdx /* 3rd arg */
c =           rcx
d =           r8
e =           rdx
y3 =          rdi

TBL =   rbp

a =     rax
b =     rbx

f =     r9
g =     r10
h =     r11
old_h = r11

T1 =    r12
y0 =    r13
y1 =    r14
y2 =    r15

y4 =    r12

/* Local variables (stack frame) */
#define frame_XFER      0
#define frame_XFER_size (4*8)
#define frame_SRND      (frame_XFER + frame_XFER_size)
#define frame_SRND_size (1*8)
#define frame_INP      (frame_SRND + frame_SRND_size)
#define frame_INP_size (1*8)
#define frame_INPEND      (frame_INP + frame_INP_size)
#define frame_INPEND_size (1*8)
#define frame_RSPSAVE      (frame_INPEND + frame_INPEND_size)
#define frame_RSPSAVE_size (1*8)
#define frame_GPRSAVE      (frame_RSPSAVE + frame_RSPSAVE_size)
#define frame_GPRSAVE_size (6*8)
#define frame_size (frame_GPRSAVE + frame_GPRSAVE_size)

#define	VMOVDQ vmovdqu /*; assume buffers not aligned  */

/* addm [mem], reg */
/* Add reg to mem using reg-mem add and store */
.macro addm p1 p2
	add	\p2, \p1
	mov	\p1, \p2
.endm


/* COPY_YMM_AND_BSWAP ymm, [mem], byte_flip_mask */
/* Load ymm with mem and byte swap each dword */
.macro COPY_YMM_AND_BSWAP p1 p2 p3
	VMOVDQ \p1, \p2
	vpshufb \p1, \p1, \p3
.endm
/* rotate_Ys */
/* Rotate values of symbols Y0...Y3 */
.macro rotate_Ys
	__Y_ = Y_0
	Y_0 = Y_1
	Y_1 = Y_2
	Y_2 = Y_3
	Y_3 = __Y_
.endm

/* RotateState */
.macro RotateState
	/* Rotate symbles a..h right */
	old_h =  h
	__TMP_ = h
	h =      g
	g =      f
	f =      e
	e =      d
	d =      c
	c =      b
	b =      a
	a =      __TMP_
.endm

/* %macro MY_VPALIGNR	YDST, YSRC1, YSRC2, RVAL */
/* YDST = {YSRC1, YSRC2} >> RVAL*8 */
.macro MY_VPALIGNR YDST, YSRC1, YSRC2, RVAL
	vperm2f128 	\YDST, \YSRC1, \YSRC2, 0x3	/* YDST = {YS1_LO, YS2_HI} */
	vpalignr 	\YDST, \YDST, \YSRC2, \RVAL	/* YDST = {YDS1, YS2} >> RVAL*8 */
.endm

.macro FOUR_ROUNDS_AND_SCHED
/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 0 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

		/* Extract w[t-7] */
		MY_VPALIGNR	YTMP0, Y_3, Y_2, 8		/* YTMP0 = W[-7] */
		/* Calculate w[t-16] + w[t-7] */
		vpaddq		YTMP0, YTMP0, Y_0		/* YTMP0 = W[-7] + W[-16] */
		/* Extract w[t-15] */
		MY_VPALIGNR	YTMP1, Y_1, Y_0, 8		/* YTMP1 = W[-15] */

		/* Calculate sigma0 */

		/* Calculate w[t-15] ror 1 */
		vpsrlq		YTMP2, YTMP1, 1
		vpsllq		YTMP3, YTMP1, (64-1)
		vpor		YTMP3, YTMP3, YTMP2		/* YTMP3 = W[-15] ror 1 */
		/* Calculate w[t-15] shr 7 */
		vpsrlq		YTMP4, YTMP1, 7			/* YTMP4 = W[-15] >> 7 */

	mov	y3, a		/* y3 = a                                       ; MAJA	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */

	add	h, [rsp+frame_XFER+0*8]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */
	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */
	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */

	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */
	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	add	d, h		/* d = k + w + h + d                            ; --	 */

	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */
	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */

	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */
	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */

	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */
	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */

	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */

	add	h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */
	add	h, y3		/* h = t1 + S0 + MAJ                            ; --	 */

RotateState

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 1 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

/*;;;;;;;;;;;;;;;;;;;;;;;;; */

		/* Calculate w[t-15] ror 8 */
		vpsrlq		YTMP2, YTMP1, 8
		vpsllq		YTMP1, YTMP1, (64-8)
		vpor		YTMP1, YTMP1, YTMP2		/* YTMP1 = W[-15] ror 8 */
		/* XOR the three components */
		vpxor		YTMP3, YTMP3, YTMP4		/* YTMP3 = W[-15] ror 1 ^ W[-15] >> 7 */
		vpxor		YTMP1, YTMP3, YTMP1		/* YTMP1 = s0 */


		/* Add three components, w[t-16], w[t-7] and sigma0 */
		vpaddq		YTMP0, YTMP0, YTMP1		/* YTMP0 = W[-16] + W[-7] + s0 */
		/* Move to appropriate lanes for calculating w[16] and w[17] */
		vperm2f128	Y_0, YTMP0, YTMP0, 0x0		/* Y_0 = W[-16] + W[-7] + s0 {BABA} */
		/* Move to appropriate lanes for calculating w[18] and w[19] */
		vpand		YTMP0, YTMP0, [.LMASK_YMM_LO ADD_RIP]	/* YTMP0 = W[-16] + W[-7] + s0 {DC00} */

		/* Calculate w[16] and w[17] in both 128 bit lanes */

		/* Calculate sigma1 for w[16] and w[17] on both 128 bit lanes */
		vperm2f128	YTMP2, Y_3, Y_3, 0x11		/* YTMP2 = W[-2] {BABA} */
		vpsrlq		YTMP4, YTMP2, 6			/* YTMP4 = W[-2] >> 6 {BABA} */


	mov	y3, a		/* y3 = a                                       ; MAJA	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	add	h, [rsp+frame_XFER+1*8]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */


	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */


	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */
	add	d, h		/* d = k + w + h + d                            ; --	 */

	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */
	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */

	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */

	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */

	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */
	add	h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */
	add	h, y3		/* h = t1 + S0 + MAJ                            ; --	 */

RotateState




/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 2 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

/*;;;;;;;;;;;;;;;;;;;;;;;;; */


		vpsrlq		YTMP3, YTMP2, 19		/* YTMP3 = W[-2] >> 19 {BABA} */
		vpsllq		YTMP1, YTMP2, (64-19)		/* YTMP1 = W[-2] << 19 {BABA} */
		vpor		YTMP3, YTMP3, YTMP1		/* YTMP3 = W[-2] ror 19 {BABA} */
		vpxor		YTMP4, YTMP4, YTMP3		/* YTMP4 = W[-2] ror 19 ^ W[-2] >> 6 {BABA} */
		vpsrlq		YTMP3, YTMP2, 61		/* YTMP3 = W[-2] >> 61 {BABA} */
		vpsllq		YTMP1, YTMP2, (64-61)		/* YTMP1 = W[-2] << 61 {BABA} */
		vpor		YTMP3, YTMP3, YTMP1		/* YTMP3 = W[-2] ror 61 {BABA} */
		vpxor		YTMP4, YTMP4, YTMP3		/* YTMP4 = s1 = (W[-2] ror 19) ^ (W[-2] ror 61) ^ (W[-2] >> 6) {BABA} */

		/* Add sigma1 to the other compunents to get w[16] and w[17] */
		vpaddq		Y_0, Y_0, YTMP4			/* Y_0 = {W[1], W[0], W[1], W[0]} */

		/* Calculate sigma1 for w[18] and w[19] for upper 128 bit lane */
		vpsrlq		YTMP4, Y_0, 6			/* YTMP4 = W[-2] >> 6 {DC--} */

	mov	y3, a		/* y3 = a                                       ; MAJA	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	add	h, [rsp+frame_XFER+2*8]		/* h = k + w + h                                ; --	 */

	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */
	mov	y2, f		/* y2 = f                                       ; CH	 */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */

	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */

	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	add	d, h		/* d = k + w + h + d                            ; --	 */
	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */

	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */
	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */
	add	h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */

	add	h, y3		/* h = t1 + S0 + MAJ                            ; --	 */

RotateState

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 3 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

/*;;;;;;;;;;;;;;;;;;;;;;;;; */

		vpsrlq		YTMP3, Y_0, 19			/* YTMP3 = W[-2] >> 19 {DC--} */
		vpsllq		YTMP1, Y_0, (64-19)		/* YTMP1 = W[-2] << 19 {DC--} */
		vpor		YTMP3, YTMP3, YTMP1		/* YTMP3 = W[-2] ror 19 {DC--} */
		vpxor		YTMP4, YTMP4, YTMP3		/* YTMP4 = W[-2] ror 19 ^ W[-2] >> 6 {DC--} */
		vpsrlq		YTMP3, Y_0, 61			/* YTMP3 = W[-2] >> 61 {DC--} */
		vpsllq		YTMP1, Y_0, (64-61)		/* YTMP1 = W[-2] << 61 {DC--} */
		vpor		YTMP3, YTMP3, YTMP1		/* YTMP3 = W[-2] ror 61 {DC--} */
		vpxor		YTMP4, YTMP4, YTMP3		/* YTMP4 = s1 = (W[-2] ror 19) ^ (W[-2] ror 61) ^ (W[-2] >> 6) {DC--} */

		/* Add the sigma0 + w[t-7] + w[t-16] for w[18] and w[19] to newly calculated sigma1 to get w[18] and w[19] */
		vpaddq		YTMP2, YTMP0, YTMP4		/* YTMP2 = {W[3], W[2], --, --} */

		/* Form w[19, w[18], w17], w[16] */
		vpblendd		Y_0, Y_0, YTMP2, 0xF0		/* Y_0 = {W[3], W[2], W[1], W[0]} */
/*		vperm2f128		Y_0, Y_0, YTMP2, 0x30 */

	mov	y3, a		/* y3 = a                                       ; MAJA	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	add	h, [rsp+frame_XFER+3*8]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */


	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */


	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */
	add	d, h		/* d = k + w + h + d                            ; --	 */
	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */

	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */

	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */

	add	h, y1		/* h = k + w + h + S0                           ; --	 */
	add	h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */
	add	h, y3		/* h = t1 + S0 + MAJ                            ; --	 */

RotateState

rotate_Ys
.endm

.macro DO_4ROUNDS

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 0 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	mov	y3, a		/* y3 = a                                       ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */
	add	h, [rsp + frame_XFER + 8*0]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */


	add	d, h		/* d = k + w + h + d                            ; --	 */
	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */

	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */


	/*add	h, y2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */

	/*add	h, y3		; h = t1 + S0 + MAJ                            ; --	 */

	RotateState

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 1 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	add	old_h, y2	/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */
	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */
	add	old_h, y3	/* h = t1 + S0 + MAJ                            ; --	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	mov	y3, a		/* y3 = a                                       ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */
	add	h, [rsp + frame_XFER + 8*1]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */


	add	d, h		/* d = k + w + h + d                            ; --	 */
	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */

	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */


	/*add	h, y2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */

	/*add	h, y3		; h = t1 + S0 + MAJ                            ; --	 */

	RotateState

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 2 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	add	old_h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */
	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */
	add	old_h, y3	/* h = t1 + S0 + MAJ                            ; --	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	mov	y3, a		/* y3 = a                                       ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */
	add	h, [rsp + frame_XFER + 8*2]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */


	add	d, h		/* d = k + w + h + d                            ; --	 */
	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */

	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */


	/*add	h, y2		; h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */

	/*add	h, y3		; h = t1 + S0 + MAJ                            ; --	 */

	RotateState

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; RND N + 3 ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */

	add	old_h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */
	mov	y2, f		/* y2 = f                                       ; CH	 */
	rorx	y0, e, 41	/* y0 = e >> 41					; S1A */
	rorx	y1, e, 18	/* y1 = e >> 18					; S1B */
	xor	y2, g		/* y2 = f^g                                     ; CH	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18)			; S1 */
	rorx	y1, e, 14	/* y1 = (e >> 14)					; S1 */
	and	y2, e		/* y2 = (f^g)&e                                 ; CH	 */
	add	old_h, y3	/* h = t1 + S0 + MAJ                            ; --	 */

	xor	y0, y1		/* y0 = (e>>41) ^ (e>>18) ^ (e>>14)		; S1 */
	rorx	T1, a, 34	/* T1 = a >> 34					; S0B */
	xor	y2, g		/* y2 = CH = ((f^g)&e)^g                        ; CH	 */
	rorx	y1, a, 39	/* y1 = a >> 39					; S0A */
	mov	y3, a		/* y3 = a                                       ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34)			; S0 */
	rorx	T1, a, 28	/* T1 = (a >> 28)					; S0 */
	add	h, [rsp + frame_XFER + 8*3]		/* h = k + w + h                                ; --	 */
	or	y3, c		/* y3 = a|c                                     ; MAJA	 */

	xor	y1, T1		/* y1 = (a>>39) ^ (a>>34) ^ (a>>28)		; S0 */
	mov	T1, a		/* T1 = a                                       ; MAJB	 */
	and	y3, b		/* y3 = (a|c)&b                                 ; MAJA	 */
	and	T1, c		/* T1 = a&c                                     ; MAJB	 */
	add	y2, y0		/* y2 = S1 + CH                                 ; --	 */


	add	d, h		/* d = k + w + h + d                            ; --	 */
	or	y3, T1		/* y3 = MAJ = (a|c)&b)|(a&c)                    ; MAJ	 */
	add	h, y1		/* h = k + w + h + S0                           ; --	 */

	add	d, y2		/* d = k + w + h + d + S1 + CH = d + t1         ; --	 */


	add	h, y2		/* h = k + w + h + S0 + S1 + CH = t1 + S0       ; --	 */

	add	h, y3		/* h = t1 + S0 + MAJ                            ; --	 */

	RotateState

.endm

/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; void sha512_rorx(const void* M, void* D, uint64_t L);
; Purpose: Updates the SHA512 digest stored at D with the message stored in M.
; The size of the message pointed to by M must be an integer multiple of SHA512
;   message blocks.
; L is the message length in SHA512 blocks
*/
.globl _gcry_sha512_transform_amd64_avx2
ELF(.type _gcry_sha512_transform_amd64_avx2,@function;)
.align 16
_gcry_sha512_transform_amd64_avx2:
	xor eax, eax

	cmp rdx, 0
	je .Lnowork

	vzeroupper

	/* Allocate Stack Space */
	mov	rax, rsp
	sub	rsp, frame_size
	and	rsp, ~(0x20 - 1)
	mov	[rsp + frame_RSPSAVE], rax

	/* Save GPRs */
	mov	[rsp + frame_GPRSAVE + 8 * 0], rbp
	mov	[rsp + frame_GPRSAVE + 8 * 1], rbx
	mov	[rsp + frame_GPRSAVE + 8 * 2], r12
	mov	[rsp + frame_GPRSAVE + 8 * 3], r13
	mov	[rsp + frame_GPRSAVE + 8 * 4], r14
	mov	[rsp + frame_GPRSAVE + 8 * 5], r15

	vpblendd	xmm0, xmm0, xmm1, 0xf0
	vpblendd	ymm0, ymm0, ymm1, 0xf0

	shl	NUM_BLKS, 7	/* convert to bytes */
	jz	.Ldone_hash
	add	NUM_BLKS, INP	/* pointer to end of data */
	mov	[rsp + frame_INPEND], NUM_BLKS

	/*; load initial digest */
	mov	a,[8*0 + CTX]
	mov	b,[8*1 + CTX]
	mov	c,[8*2 + CTX]
	mov	d,[8*3 + CTX]
	mov	e,[8*4 + CTX]
	mov	f,[8*5 + CTX]
	mov	g,[8*6 + CTX]
	mov	h,[8*7 + CTX]

	vmovdqa	BYTE_FLIP_MASK, [.LPSHUFFLE_BYTE_FLIP_MASK ADD_RIP]

.Loop0:
	lea	TBL,[.LK512 ADD_RIP]

	/*; byte swap first 16 dwords */
	COPY_YMM_AND_BSWAP	Y_0, [INP + 0*32], BYTE_FLIP_MASK
	COPY_YMM_AND_BSWAP	Y_1, [INP + 1*32], BYTE_FLIP_MASK
	COPY_YMM_AND_BSWAP	Y_2, [INP + 2*32], BYTE_FLIP_MASK
	COPY_YMM_AND_BSWAP	Y_3, [INP + 3*32], BYTE_FLIP_MASK

	mov	[rsp + frame_INP], INP

	/*; schedule 64 input dwords, by doing 12 rounds of 4 each */
	movq	[rsp + frame_SRND],4

.align 16
.Loop1:
	vpaddq	XFER, Y_0, [TBL + 0*32]
	vmovdqa [rsp + frame_XFER], XFER
	FOUR_ROUNDS_AND_SCHED

	vpaddq	XFER, Y_0, [TBL + 1*32]
	vmovdqa [rsp + frame_XFER], XFER
	FOUR_ROUNDS_AND_SCHED

	vpaddq	XFER, Y_0, [TBL + 2*32]
	vmovdqa [rsp + frame_XFER], XFER
	FOUR_ROUNDS_AND_SCHED

	vpaddq	XFER, Y_0, [TBL + 3*32]
	vmovdqa [rsp + frame_XFER], XFER
	add	TBL, 4*32
	FOUR_ROUNDS_AND_SCHED

	subq	[rsp + frame_SRND], 1
	jne	.Loop1

	movq	[rsp + frame_SRND], 2
.Loop2:
	vpaddq	XFER, Y_0, [TBL + 0*32]
	vmovdqa [rsp + frame_XFER], XFER
	DO_4ROUNDS
	vpaddq	XFER, Y_1, [TBL + 1*32]
	vmovdqa [rsp + frame_XFER], XFER
	add	TBL, 2*32
	DO_4ROUNDS

	vmovdqa	Y_0, Y_2
	vmovdqa	Y_1, Y_3

	subq	[rsp + frame_SRND], 1
	jne	.Loop2

	addm	[8*0 + CTX],a
	addm	[8*1 + CTX],b
	addm	[8*2 + CTX],c
	addm	[8*3 + CTX],d
	addm	[8*4 + CTX],e
	addm	[8*5 + CTX],f
	addm	[8*6 + CTX],g
	addm	[8*7 + CTX],h

	mov	INP, [rsp + frame_INP]
	add	INP, 128
	cmp	INP, [rsp + frame_INPEND]
	jne	.Loop0

.Ldone_hash:

	/* Restore GPRs */
	mov	rbp, [rsp + frame_GPRSAVE + 8 * 0]
	mov	rbx, [rsp + frame_GPRSAVE + 8 * 1]
	mov	r12, [rsp + frame_GPRSAVE + 8 * 2]
	mov	r13, [rsp + frame_GPRSAVE + 8 * 3]
	mov	r14, [rsp + frame_GPRSAVE + 8 * 4]
	mov	r15, [rsp + frame_GPRSAVE + 8 * 5]

	/* Restore Stack Pointer */
	mov	rsp, [rsp + frame_RSPSAVE]

	vzeroall

	mov	eax, frame_size + 31
.Lnowork:
	ret

/*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; */
/*;; Binary Data */

.align 64
/* K[t] used in SHA512 hashing */
.LK512:
	.quad	0x428a2f98d728ae22,0x7137449123ef65cd
	.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.quad	0x3956c25bf348b538,0x59f111f1b605d019
	.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.quad	0xd807aa98a3030242,0x12835b0145706fbe
	.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
	.quad	0x9bdc06a725c71235,0xc19bf174cf692694
	.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
	.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
	.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.quad	0x983e5152ee66dfab,0xa831c66d2db43210
	.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
	.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
	.quad	0x06ca6351e003826f,0x142929670a0e6e70
	.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
	.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
	.quad	0x81c2c92e47edaee6,0x92722c851482353b
	.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
	.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
	.quad	0xd192e819d6ef5218,0xd69906245565a910
	.quad	0xf40e35855771202a,0x106aa07032bbd1b8
	.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
	.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
	.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
	.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
	.quad	0x90befffa23631e28,0xa4506cebde82bde9
	.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
	.quad	0xca273eceea26619c,0xd186b8c721c0c207
	.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
	.quad	0x113f9804bef90dae,0x1b710b35131c471b
	.quad	0x28db77f523047d84,0x32caab7b40c72493
	.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
	.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817

.align 32

/* Mask for byte-swapping a couple of qwords in an XMM register using (v)pshufb. */
.LPSHUFFLE_BYTE_FLIP_MASK: .octa 0x08090a0b0c0d0e0f0001020304050607
			   .octa 0x18191a1b1c1d1e1f1011121314151617

.LMASK_YMM_LO:		   .octa 0x00000000000000000000000000000000
			   .octa 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

#endif
#endif
