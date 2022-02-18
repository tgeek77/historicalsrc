	TITLE   fprims

;	Fast 8086 assembly primitives for add, subtract, rotate left,
;	and set precision bits for multiprecision integers.
;	Callable from Microsoft C or Turbo C.
;	Implemented Jan 1987 by Zhahai Stewart.
;	Used by Philip Zimmermann's RSA public key cryptography library.

;	Much faster primitives that implement a combined multiply/modulo
;	operation are available by contacting Philip Zimmermann, 
;	at Boulder Software Engineering, phone (303)444-4541

;	Static Name Aliases
;
_TEXT	SEGMENT  BYTE PUBLIC 'CODE'
_TEXT	ENDS
CONST	SEGMENT  WORD PUBLIC 'CONST'
CONST	ENDS
_BSS	SEGMENT  WORD PUBLIC 'BSS'
_BSS	ENDS
_DATA	SEGMENT  WORD PUBLIC 'DATA'
_DATA	ENDS
DGROUP	GROUP	CONST,	_BSS,	_DATA
	ASSUME  CS: _TEXT, DS: DGROUP, SS: DGROUP, ES: DGROUP
PUBLIC	_P_SETP		;set global precision, maximum of 1024 bits
PUBLIC  _P_ADDC		;multiprecision add with carry
PUBLIC  _P_SUBB		;multiprecision subtract with borrow
PUBLIC  _P_ROTL		;multiprecision rotate left 1 bit
_DATA	SEGMENT
_DATA	ENDS
_TEXT      SEGMENT

mswoff	dw	(?)
adcx	dw	(?)
sbbx	dw	(?)
rclx	dw	(?)

;--------------------------------------------------------------
;	precision=bp+4		precision in bits
;				prec means precision in wds

	PUBLIC	_P_SETP
_P_SETP	PROC NEAR
	push	bp
	mov	bp,sp
	mov	ax,[bp+4]

;	add	ax,15	round up
;	shr	ax,4	number of words
;	dec	ax	number - 1
;	shl	ax,4	back to number of bits: 16 * (prec - 1)
	dec	ax	; faster alternate way to do same thing
	and	al,0F0h

	cmp	ax,1008	; 16 * (64-1)
	jg	x_setp	; out of range

	shr	ax,1			; ax = 8 * (prec - 1)
	shr	ax,1			; ax = 4 * (prec - 1)

	mov	bx,offset adc01
	sub	bx,ax
	mov	cs:[adcx],bx	; adcx = &adc01 - 4 * (prec - 1)

	mov	bx,offset sbb01
	sub	bx,ax
	mov	cs:[sbbx],bx	; sbbx = &sbb01 - 4 * (prec - 1)

	mov	bx,offset rcl01
	shr	ax,1			; ax = 2 * (prec - 1)
	mov	cs:[mswoff],ax	; mswoff = 2 * (prec-1) = msword offset
	sub	bx,ax
	shr	ax,1			; ax = prec - 1
	sub	bx,ax
	mov	cs:[rclx],bx	; rclx = &rcl01 - 3 * (prec - 1)

x_setp:	pop	bp
	ret
_P_SETP	ENDP


;--------------------------------------------------------------
;	r1=bp+4
;	r2=bp+6
;	carry=bp+8

	PUBLIC	_P_ADDC
_P_ADDC	PROC NEAR
	push	bp
	mov	bp,sp
	push	si
	push	di

	mov	di,[bp+4]	; r1
	mov	si,[bp+6]	; r2
	add	di,cs:[mswoff]	; offset to msw
	cld			; go fwd

	mov	al,0FFh		; set cy flag if carry non-zero
	add	al,[bp+8]	; carry in
	call	cs:[adcx]
	mov	ax,0		; don't affect flags
	rcl	ax,1		; set ax = 0 if no borrow, 1 if borrow out

	pop	di
	pop	si
	mov	sp,bp
	pop	bp
	ret	
_P_ADDC	ENDP

;--------------------------------------------------------------
;	r1=bp+4
;	r2=bp+6
;	borrow=bp+8

	PUBLIC	_P_SUBB
_P_SUBB	PROC NEAR
	push	bp
	mov	bp,sp
	push	si
	push	di

	mov	di,[bp+4]	; r1
	mov	si,[bp+6]	; r2
	add	di,cs:[mswoff]	; offset to msw
	cld			; go fwd

	mov	al,0FFh		; set cy flag if borrow non-zero
	add	al,[bp+8]	; borrow
	call	cs:[sbbx]
	mov	ax,0		; don't affect flags
	rcl	ax,1		; set ax = 0 if no borrow, 1 if borrow out

	pop	di
	pop	si
	mov	sp,bp
	pop	bp
	ret	
_P_SUBB	ENDP

;--------------------------------------------------------------
;	r1=bp+4
;	c=bp+6

	PUBLIC	_P_ROTL
_P_ROTL	PROC NEAR
	push	bp
	mov	bp,sp
	push	di

	mov	di,[bp+4]	; r1
	add	di,cs:[mswoff]	; offset to msw
	mov	al,0FFh
	add	al,[bp+6]	; c (carry)
	call	cs:[rclx]
	mov	ax,0		; don't affect flags
	rcl	ax,1		; set ax = 0 if no carry, 1 if carry out

	pop	di
	mov	sp,bp
	pop	bp
	ret	
_P_ROTL	ENDP

;========================================================================
dummy	proc	near

adc64:	lodsw
	adc	[di-126],ax
	lodsw
	adc	[di-124],ax
	lodsw
	adc	[di-122],ax
	lodsw
	adc	[di-120],ax
	lodsw
	adc	[di-118],ax
	lodsw
	adc	[di-116],ax
	lodsw
	adc	[di-114],ax
	lodsw
	adc	[di-112],ax
	lodsw
	adc	[di-110],ax
	lodsw
	adc	[di-108],ax
	lodsw
	adc	[di-106],ax
	lodsw
	adc	[di-104],ax
	lodsw
	adc	[di-102],ax
	lodsw
	adc	[di-100],ax
	lodsw
	adc	[di-98],ax
	lodsw
	adc	[di-96],ax
	lodsw
	adc	[di-94],ax
	lodsw
	adc	[di-92],ax
	lodsw
	adc	[di-90],ax
	lodsw
	adc	[di-88],ax
	lodsw
	adc	[di-86],ax
	lodsw
	adc	[di-84],ax
	lodsw
	adc	[di-82],ax
	lodsw
	adc	[di-80],ax
	lodsw
	adc	[di-78],ax
	lodsw
	adc	[di-76],ax
	lodsw
	adc	[di-74],ax
	lodsw
	adc	[di-72],ax
	lodsw
	adc	[di-70],ax
	lodsw
	adc	[di-68],ax
	lodsw
	adc	[di-66],ax
	lodsw
	adc	[di-64],ax
	lodsw
	adc	[di-62],ax
	lodsw
	adc	[di-60],ax
	lodsw
	adc	[di-58],ax
	lodsw
	adc	[di-56],ax
	lodsw
	adc	[di-54],ax
	lodsw
	adc	[di-52],ax
	lodsw
	adc	[di-50],ax
	lodsw
	adc	[di-48],ax
	lodsw
	adc	[di-46],ax
	lodsw
	adc	[di-44],ax
	lodsw
	adc	[di-42],ax
	lodsw
	adc	[di-40],ax
	lodsw
	adc	[di-38],ax
	lodsw
	adc	[di-36],ax
	lodsw
	adc	[di-34],ax
	lodsw
	adc	[di-32],ax
	lodsw
	adc	[di-30],ax
	lodsw
	adc	[di-28],ax
	lodsw
	adc	[di-26],ax
	lodsw
	adc	[di-24],ax
	lodsw
	adc	[di-22],ax
	lodsw
	adc	[di-20],ax
	lodsw
	adc	[di-18],ax
	lodsw
	adc	[di-16],ax
	lodsw
	adc	[di-14],ax
	lodsw
	adc	[di-12],ax
	lodsw
	adc	[di-10],ax
	lodsw
	adc	[di-8],ax
	lodsw
	adc	[di-6],ax
	lodsw
	adc	[di-4],ax
	lodsw
	adc	[di-2],ax
adc01:	lodsw
	adc	[di],ax
	ret

sbb64:	lodsw
	sbb	[di-126],ax
	lodsw
	sbb	[di-124],ax
	lodsw
	sbb	[di-122],ax
	lodsw
	sbb	[di-120],ax
	lodsw
	sbb	[di-118],ax
	lodsw
	sbb	[di-116],ax
	lodsw
	sbb	[di-114],ax
	lodsw
	sbb	[di-112],ax
	lodsw
	sbb	[di-110],ax
	lodsw
	sbb	[di-108],ax
	lodsw
	sbb	[di-106],ax
	lodsw
	sbb	[di-104],ax
	lodsw
	sbb	[di-102],ax
	lodsw
	sbb	[di-100],ax
	lodsw
	sbb	[di-98],ax
	lodsw
	sbb	[di-96],ax
	lodsw
	sbb	[di-94],ax
	lodsw
	sbb	[di-92],ax
	lodsw
	sbb	[di-90],ax
	lodsw
	sbb	[di-88],ax
	lodsw
	sbb	[di-86],ax
	lodsw
	sbb	[di-84],ax
	lodsw
	sbb	[di-82],ax
	lodsw
	sbb	[di-80],ax
	lodsw
	sbb	[di-78],ax
	lodsw
	sbb	[di-76],ax
	lodsw
	sbb	[di-74],ax
	lodsw
	sbb	[di-72],ax
	lodsw
	sbb	[di-70],ax
	lodsw
	sbb	[di-68],ax
	lodsw
	sbb	[di-66],ax
	lodsw
	sbb	[di-64],ax
	lodsw
	sbb	[di-62],ax
	lodsw
	sbb	[di-60],ax
	lodsw
	sbb	[di-58],ax
	lodsw
	sbb	[di-56],ax
	lodsw
	sbb	[di-54],ax
	lodsw
	sbb	[di-52],ax
	lodsw
	sbb	[di-50],ax
	lodsw
	sbb	[di-48],ax
	lodsw
	sbb	[di-46],ax
	lodsw
	sbb	[di-44],ax
	lodsw
	sbb	[di-42],ax
	lodsw
	sbb	[di-40],ax
	lodsw
	sbb	[di-38],ax
	lodsw
	sbb	[di-36],ax
	lodsw
	sbb	[di-34],ax
	lodsw
	sbb	[di-32],ax
	lodsw
	sbb	[di-30],ax
	lodsw
	sbb	[di-28],ax
	lodsw
	sbb	[di-26],ax
	lodsw
	sbb	[di-24],ax
	lodsw
	sbb	[di-22],ax
	lodsw
	sbb	[di-20],ax
	lodsw
	sbb	[di-18],ax
	lodsw
	sbb	[di-16],ax
	lodsw
	sbb	[di-14],ax
	lodsw
	sbb	[di-12],ax
	lodsw
	sbb	[di-10],ax
	lodsw
	sbb	[di-8],ax
	lodsw
	sbb	[di-6],ax
	lodsw
	sbb	[di-4],ax
	lodsw
	sbb	[di-2],ax
sbb01:	lodsw
	sbb	[di],ax
	ret


rcl64:	rcl	word ptr [di-126],1
	rcl	word ptr [di-124],1
	rcl	word ptr [di-122],1
	rcl	word ptr [di-120],1
	rcl	word ptr [di-118],1
	rcl	word ptr [di-116],1
	rcl	word ptr [di-114],1
	rcl	word ptr [di-112],1
	rcl	word ptr [di-110],1
	rcl	word ptr [di-108],1
	rcl	word ptr [di-106],1
	rcl	word ptr [di-104],1
	rcl	word ptr [di-102],1
	rcl	word ptr [di-100],1
	rcl	word ptr [di-98],1
	rcl	word ptr [di-96],1
	rcl	word ptr [di-94],1
	rcl	word ptr [di-92],1
	rcl	word ptr [di-90],1
	rcl	word ptr [di-88],1
	rcl	word ptr [di-86],1
	rcl	word ptr [di-84],1
	rcl	word ptr [di-82],1
	rcl	word ptr [di-80],1
	rcl	word ptr [di-78],1
	rcl	word ptr [di-76],1
	rcl	word ptr [di-74],1
	rcl	word ptr [di-72],1
	rcl	word ptr [di-70],1
	rcl	word ptr [di-68],1
	rcl	word ptr [di-66],1
	rcl	word ptr [di-64],1
	rcl	word ptr [di-62],1
	rcl	word ptr [di-60],1
	rcl	word ptr [di-58],1
	rcl	word ptr [di-56],1
	rcl	word ptr [di-54],1
	rcl	word ptr [di-52],1
	rcl	word ptr [di-50],1
	rcl	word ptr [di-48],1
	rcl	word ptr [di-46],1
	rcl	word ptr [di-44],1
	rcl	word ptr [di-42],1
	rcl	word ptr [di-40],1
	rcl	word ptr [di-38],1
	rcl	word ptr [di-36],1
	rcl	word ptr [di-34],1
	rcl	word ptr [di-32],1
	rcl	word ptr [di-30],1
	rcl	word ptr [di-28],1
	rcl	word ptr [di-26],1
	rcl	word ptr [di-24],1
	rcl	word ptr [di-22],1
	rcl	word ptr [di-20],1
	rcl	word ptr [di-18],1
	rcl	word ptr [di-16],1
	rcl	word ptr [di-14],1
	rcl	word ptr [di-12],1
	rcl	word ptr [di-10],1
	rcl	word ptr [di-8],1
	rcl	word ptr [di-6],1
	rcl	word ptr [di-4],1
	rcl	word ptr [di-2],1
rcl01:	rcl	word ptr [di],1
	ret
dummy	endp

_TEXT	ENDS
END
