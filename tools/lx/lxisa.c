/* lxisa -- which vector instruction sets can actually EXECUTE under us?
 *
 * Firefox died with an Invalid Opcode on
 *
 *     c4 e3 d1 ce ea 00   VGF2P8AFFINEQB xmm5, xmm5, xmm2, 0
 *
 * which is GFNI, and the question that matters is whether that is OS-DEV's
 * fault or the emulator's. The host CPU has GFNI and runs the instruction
 * natively; QEMU's TCG advertises a great deal in `-cpu max` that it cannot
 * necessarily execute, and a #UD on a legitimately-advertised instruction is
 * indistinguishable from a kernel that forgot to enable the state.
 *
 * So: try them in order, announcing each BEFORE executing it. We kill a ring-3
 * task on #UD rather than raising SIGILL, so the last line printed names the
 * instruction that was not there. That is a definitive answer either way, and
 * it is the same answer on real hardware -- where this should print every line.
 * (M2007)
 */
#include <stdio.h>

int main(void)
{
    setvbuf(stdout, 0, _IONBF, 0);      /* unbuffered: the last line must survive a kill */

    puts("LXISA: trying SSE2 (movdqa)");
    __asm__ volatile("movdqa %xmm0, %xmm1");
    puts("LXISA: SSE2 ok");

    puts("LXISA: trying AVX (vzeroupper / vmovaps ymm)");
    __asm__ volatile("vmovaps %ymm0, %ymm1; vzeroupper");
    puts("LXISA: AVX ok");

    puts("LXISA: trying AVX2 (vpaddb ymm)");
    __asm__ volatile("vpaddb %ymm1, %ymm1, %ymm2; vzeroupper");
    puts("LXISA: AVX2 ok");

    puts("LXISA: trying FMA (vfmadd213ps)");
    __asm__ volatile("vfmadd213ps %xmm1, %xmm1, %xmm2");
    puts("LXISA: FMA ok");

    puts("LXISA: trying AES-NI (aesenc)");
    __asm__ volatile("aesenc %xmm1, %xmm2");
    puts("LXISA: AES-NI ok");

    puts("LXISA: trying PCLMULQDQ");
    __asm__ volatile("pclmulqdq $0, %xmm1, %xmm2");
    puts("LXISA: PCLMULQDQ ok");

    /* The one Firefox actually used, byte for byte. */
    puts("LXISA: trying GFNI (vgf2p8affineqb) -- the one Firefox used");
    __asm__ volatile(".byte 0xc4,0xe3,0xd1,0xce,0xea,0x00");
    puts("LXISA: GFNI ok");

    puts("LXISA: trying VAES (vaesenc ymm)");
    __asm__ volatile(".byte 0xc4,0xe2,0x6d,0xdc,0xd9");   /* vaesenc ymm3,ymm2,ymm1 */
    puts("LXISA: VAES ok");

    /* EXECUTING IS NOT THE SAME AS COMPUTING. When the kernel completes an
     * instruction in software, "it did not fault" says nothing about whether
     * the ANSWER is right -- and a silently wrong crypto primitive is far worse
     * than a #UD. These two vectors were produced by the real instruction on
     * the host CPU, so they are the hardware's own answer, and a software
     * implementation that disagrees anywhere fails here. (M2007) */
    {
        static const unsigned char GF128_EXPECT[16] = {0xf0,0x59,0x03,0xa9,0x33,0xcf,0x96,0x3c,0x59,0xc3,0x99,0xcf,0x55,0x03,0xf0,0xa6};
        static const unsigned char GF256_EXPECT[32] = {0x96,0x3f,0x65,0xcf,0x55,0xa9,0xf0,0x5a,0x3f,0xa5,0xff,0xa9,0x33,0x65,0x96,0xc0,0x59,0xf0,0xaa,0x4b,0xd1,0x84,0xdd,0x22,0x47,0x11,0x4b,0x1d,0x4b,0x1d,0xbb,0xed};
        unsigned char x[32], A[32], got[32];
        int bad = 0;
        for (int i = 0; i < 32; i++) { x[i] = (unsigned char)(i*7+1); A[i] = (unsigned char)(i*31+5); }

        __asm__ volatile("movdqu (%1),%%xmm0\n\tmovdqu (%2),%%xmm1\n\t"
            ".byte 0xc4,0xe3,0xf9,0xce,0xc1,0x5a\n\tmovdqu %%xmm0,(%0)"
            : : "r"(got), "r"(x), "r"(A) : "xmm0","xmm1","memory");
        for (int i = 0; i < 16; i++) if (got[i] != GF128_EXPECT[i]) bad++;
        printf("LXISA: gfni 128-bit result %s the hardware's (%d byte(s) differ)\n",
               bad ? "DIFFERS FROM" : "matches", bad);

        int bad2 = 0;
        __asm__ volatile("vmovdqu (%1),%%ymm0\n\tvmovdqu (%2),%%ymm1\n\t"
            ".byte 0xc4,0xe3,0xfd,0xce,0xc1,0x3c\n\tvmovdqu %%ymm0,(%0)\n\tvzeroupper"
            : : "r"(got), "r"(x), "r"(A) : "ymm0","ymm1","memory");
        for (int i = 0; i < 32; i++) if (got[i] != GF256_EXPECT[i]) bad2++;
        printf("LXISA: gfni 256-bit result %s the hardware's (%d byte(s) differ)\n",
               bad2 ? "DIFFERS FROM" : "matches", bad2);

        /* ...and the memory-operand form, which takes a different decode path:
         * 189 of libxul's 702 sites use one. */
        int bad3 = 0;
        __asm__ volatile("movdqu (%1),%%xmm0\n\t"
            ".byte 0xc4,0xe3,0xf9,0xce,0x02,0x5a\n\tmovdqu %%xmm0,(%0)"
            : : "r"(got), "r"(x), "d"(A) : "xmm0","memory");
        for (int i = 0; i < 16; i++) if (got[i] != GF128_EXPECT[i]) bad3++;
        printf("LXISA: gfni with a MEMORY operand %s (%d byte(s) differ)\n",
               bad3 ? "DIFFERS" : "matches", bad3);

        if (bad || bad2 || bad3) { puts("LXISA: FAILED -- a wrong answer is worse than a fault"); return 1; }
    }

    puts("LXISA: all probed instruction sets executed");
    return 0;
}
