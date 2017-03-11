/* vectors.s */
.cpu cortex-m3
.thumb

;@-----------------------
.thumb_func
.globl __lshrdi3
.globl __aeabi_llsr
__aeabi_llsr:
        lsr     r0, r2
        mov     r3, r1
        lsr     r1, r2
        mov     ip, r3
        sub     r2, #32
        lsr     r3, r2
        orr     r0, r3
        neg     r2, r2
        mov     r3, ip
        lsl     r3, r2
        orr     r0, r3
    bx lr
.thumb_func
.globl __aeabi_llsl
__aeabi_llsl:
        lsl     r1, r2
        mov     r3, r0
        lsl     r0, r2
        mov     ip, r3
        sub     r2, #32
        lsl     r3, r2
        orr     r1, r3
        neg     r2, r2
        mov     r3, ip
        lsr     r3, r2
        orr     r1, r3
    bx lr
.end
