/* LxJava.java -- A JVM RUNNING HERE, DOING WHAT MINECRAFT MAKES A JVM DO (M2393).
 *
 * HotSpot leans on the kernel harder than any program this OS has run, and in
 * ways that are silent when they go wrong. It does not test for null or for a
 * zero divisor: it lets the hardware fault and resumes at a handler-chosen
 * address. A safepoint is a load from a page the VM protects when it wants
 * every thread to stop. A stack overflow is a guard page it re-arms after each
 * one. So each check below does, on purpose, one of those things -- in the
 * interpreter first and then again once the JIT has compiled the method,
 * because the two take different paths to the same signal -- and says which
 * held. A kernel that gets one of them wrong does not produce an error
 * message; it produces a thread spinning in its own fault handler, a VM that
 * never reaches a safepoint, or a wrong answer.
 *
 * The rest is what Minecraft itself leans on: many threads and contended
 * monitors, a collector under allocation pressure, lambdas and streams (a few
 * thousand classes spun at run time), direct buffers, the intrinsics HotSpot
 * compiles to AVX, file I/O, and FFM downcalls -- LWJGL 3.4 on JDK 25 reaches
 * every native function through the FFM linker.
 *
 * Output: one "LXJAVA: ok|FAIL ..." line per check and a RESULT line; the
 * exit status is the number of failures. */
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.stream.*;
import java.util.zip.CRC32;

public class LxJava {
    static int fails;
    static void check(boolean ok, String what) {
        System.out.println("LXJAVA: " + (ok ? "ok   " : "FAIL ") + what);
        if (!ok) fails++;
    }
    static long t0 = System.nanoTime();
    static String ms() { return String.format("%.0f ms", (System.nanoTime() - t0) / 1e6); }

    /* Implicit null check: s.length() on null faults in the hardware. */
    static int len(String s) { return s.length(); }
    static int npeRound(int n) {
        int caught = 0;
        for (int i = 0; i < n; i++) {
            String s = (i & 1) == 0 ? null : "abc";
            try { len(s); } catch (NullPointerException e) { caught++; }
        }
        return caught;
    }
    /* Implicit divide-by-zero: idiv faults, SIGFPE, ArithmeticException. */
    static int div(int a, int b) { return a / b; }
    static long divRound(int n) {
        long caught = 0;
        for (int i = 0; i < n; i++) {
            try { div(i, i & 3); } catch (ArithmeticException e) { caught++; }
        }
        return caught;
    }
    static int depth;
    static void recurse() { depth++; recurse(); }

    public static void main(String[] args) throws Throwable {
        System.out.println("LXJAVA: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version")
                + ", " + Runtime.getRuntime().availableProcessors() + " CPUs, max heap "
                + (Runtime.getRuntime().maxMemory() >> 20) + " MiB, GC "
                + java.lang.management.ManagementFactory.getGarbageCollectorMXBeans().stream()
                      .map(b -> b.getName()).collect(Collectors.joining("+")));

        /* 1. null checks: interpreted (few iterations), then compiled */
        int c1 = npeRound(20);
        check(c1 == 10, "implicit NullPointerException, interpreter: " + c1 + "/10 caught");
        int c2 = 0; for (int r = 0; r < 50; r++) c2 += npeRound(10000);
        check(c2 == 250000, "implicit NullPointerException after JIT warm-up: " + c2 + "/250000 caught (" + ms() + ")");

        /* 2. division by zero */
        long d1 = divRound(40);
        check(d1 == 10, "ArithmeticException / by zero, interpreter: " + d1 + "/10");
        long d2 = 0; for (int r = 0; r < 50; r++) d2 += divRound(20000);
        check(d2 == 250000, "ArithmeticException / by zero after JIT warm-up: " + d2 + "/250000 (" + ms() + ")");

        /* 3. stack overflow, three times: the guard zone must be re-armed each time */
        int so = 0; int[] depths = new int[3];
        for (int k = 0; k < 3; k++) {
            depth = 0;
            try { recurse(); } catch (StackOverflowError e) { so++; depths[k] = depth; }
        }
        check(so == 3, "StackOverflowError caught 3 times, depths " + Arrays.toString(depths));

        /* 4. threads, a contended monitor, and a safepoint while they run */
        final int NT = 8;
        final long[] counter = {0};
        final Object lock = new Object();
        AtomicLong spins = new AtomicLong();
        Thread[] ts = new Thread[NT];
        for (int i = 0; i < NT; i++) {
            ts[i] = new Thread(() -> {
                long local = 0;
                for (int k = 0; k < 200000; k++) {
                    synchronized (lock) { counter[0]++; }
                    local += k ^ (k >>> 3);
                }
                spins.addAndGet(local);
            }, "lxjava-worker-" + i);
            ts[i].start();
        }
        for (int g = 0; g < 5; g++) { System.gc(); Thread.sleep(20); }   /* safepoints mid-run */
        for (Thread t : ts) t.join();
        check(counter[0] == (long) NT * 200000, NT + " threads x 200000 contended monitor entries = " + counter[0]
                + ", with 5 safepoint GCs while they ran (" + ms() + ")");

        /* 5. the collector under pressure; a weak reference must clear */
        Object marker = new Object();
        WeakReference<Object> weak = new WeakReference<>(marker);
        marker = null;
        ArrayDeque<byte[]> keep = new ArrayDeque<>();
        long allocated = 0;
        for (int i = 0; i < 3000; i++) {                  /* ~3 GiB allocated, ~64 MiB live at a time */
            byte[] b = new byte[1 << 20];
            b[i & 1023] = (byte) i;
            keep.addLast(b); allocated += b.length;
            if (keep.size() > 64) keep.removeFirst();
        }
        System.gc();
        check(weak.get() == null && keep.size() == 64, "allocated " + (allocated >> 20) + " MiB through the collector; weak ref cleared "
                + (weak.get() == null) + " (" + ms() + ")");

        /* 6. JIT'd arithmetic has to agree with the closed form */
        long sum = 0;
        for (int r = 0; r < 20; r++) { long s = 0; for (long i = 0; i < 1_000_000; i++) s += i * i; sum = s; }
        long want = 999_999L * 1_000_000L * 1_999_999L / 6;
        check(sum == want, "sum of squares below 10^6 = " + sum + " (want " + want + ")");

        /* 7. intrinsics: the paths HotSpot compiles to AVX/SHA/CLMUL */
        byte[] data = new byte[1 << 20];
        new Random(42).nextBytes(data);
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        CRC32 crc = new CRC32(); crc.update(data);
        int[] arr = new Random(7).ints(1_000_000).toArray();
        Arrays.sort(arr);
        boolean sorted = true; for (int i = 1; i < arr.length; i++) if (arr[i - 1] > arr[i]) { sorted = false; break; }
        BigInteger f = BigInteger.ONE; for (int i = 2; i <= 500; i++) f = f.multiply(BigInteger.valueOf(i));
        check(sorted && f.bitLength() == 3768 && sha.length() == 64,
                "Arrays.sort 10^6 ints, 500! (" + f.bitLength() + " bits), SHA-256 " + sha.substring(0, 16) + "..., CRC32 "
                + Long.toHexString(crc.getValue()));

        /* 8. lambdas, streams, invokedynamic: classes spun at run time */
        Map<Integer, Long> hist = IntStream.range(0, 200000).parallel().boxed()
                .collect(Collectors.groupingBy(i -> i % 7, Collectors.counting()));
        long total = hist.values().stream().mapToLong(Long::longValue).sum();
        check(total == 200000 && hist.size() == 7, "parallel stream over the common pool: " + hist.size() + " buckets, " + total + " items");

        /* 9. direct (off-heap) memory, as LWJGL's MemoryUtil uses it */
        ByteBuffer bb = ByteBuffer.allocateDirect(64 << 20);
        for (int i = 0; i < bb.capacity(); i += 4096) bb.putInt(i, i);
        boolean dok = true; for (int i = 0; i < bb.capacity(); i += 4096) if (bb.getInt(i) != i) { dok = false; break; }
        check(dok, "64 MiB direct buffer written and read back");

        /* 10. files: NIO write/read, and a mapped file */
        Path p = Files.createTempFile("lxjava", ".bin");
        Files.write(p, data);
        byte[] back = Files.readAllBytes(p);
        boolean mok;
        try (FileChannel ch = FileChannel.open(p, StandardOpenOption.READ)) {
            MappedByteBuffer mb = ch.map(FileChannel.MapMode.READ_ONLY, 0, data.length);
            mok = mb.get(12345) == data[12345] && mb.get(data.length - 1) == data[data.length - 1];
        }
        Files.delete(p);
        check(Arrays.equals(back, data) && mok, "1 MiB file written, read back and mmap'd identically (" + p + ")");

        /* 11. FFM downcall -- how LWJGL 3.4 calls every native function on JDK 25 */
        Linker linker = Linker.nativeLinker();
        MethodHandle strlen = linker.downcallHandle(linker.defaultLookup().find("strlen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        long n;
        try (Arena arena = Arena.ofConfined()) { n = (long) strlen.invokeExact(arena.allocateFrom("minecraft")); }
        check(n == 9, "FFM downcall strlen(\"minecraft\") = " + n);

        /* 12. time */
        long a = System.nanoTime(); Thread.sleep(100); long el = (System.nanoTime() - a) / 1_000_000;
        check(el >= 99 && el < 1000, "Thread.sleep(100) took " + el + " ms");

        System.out.println("LXJAVA: RESULT " + (fails == 0 ? "PASS" : "FAIL") + " (" + fails + " check(s) failed) in " + ms());
        System.exit(fails);
    }
}
