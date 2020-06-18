### regtest status for FreeBSD

All tests are on FreeBSD 12.1.

** note ** run 'kldload mqueuefs' before running the tests, otherwise none/tests/mq will fail

## amd64 / GCC results

# Tests in none

98.0% good

```
== 205 tests, 4 stderr failures, 3 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
none/tests/coolo_sigaction               (stdout)
none/tests/coolo_sigaction               (stderr)
none/tests/faultstatus                   (stderr)
none/tests/pending                       (stdout)
none/tests/pending                       (stderr)
none/tests/sigstackgrowth                (stdout)
none/tests/sigstackgrowth                (stderr)
```

Most of these are signal issues.  

# Tests in memcheck

99.8% good

```
== 244 tests, 3 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/descr_belowsp             (stderr)
memcheck/tests/gone_abrt_xml             (stderr)
memcheck/tests/sigaltstack               (stderr)
```

descr_belowsp - missing info on stack guard in message. See issue #101  
gone_abrt_xml - differences in signal details. See issue #102  
sigaltstack - SIGSEGV handling issue  

## Tests in massif, callgrind and cachegrind, dhat

100% good

# Tests in gdbserver_tests

90% good

```
== 20 tests, 2 stderr failures, 1 stdout failure, 1 stderrB failure, 3 stdoutB failures, 0 post failures ==
gdbserver_tests/mcsignopass              (stderr)
gdbserver_tests/mcsignopass              (stdoutB)
gdbserver_tests/mcsigpass                (stderr)
gdbserver_tests/mcsigpass                (stdoutB)
```

mcsignopass - guest terminating with SIGSEGV  
mcsigpass - guest getting SIGSEGV rather than SIGBUS  

# Tests in helgrind

Helgrind - 96.4% good

```
== 55 tests, 2 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
helgrind/tests/pth_cond_destroy_busy     (stderr)
helgrind/tests/tls_threads               (stderr)

```
pth_cond_destroy_busy - one missing race error  
tls_threads - a test for Linux-specific detection of tls which can't work on FreeBSD  

# Tests in drd

DRD - 97.6% good

```
== 126 tests, 3 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
drd/tests/dlopen                         (stdout)
drd/tests/dlopen                         (stderr)
drd/tests/sigaltstack                    (stderr)
drd/tests/std_list                       (stderr)
```

dlopen - crash, may need some hooks for dlopen. See issue #57  
sigaltstack - sigsegv in guest  
std_list - lots of errors related to setlocale  

## amd64 / clang results

As amd64 / GCC except the following extra failures

# Tests in none

```
none/tests/amd64/ssse3_misaligned
```
See issue #46

# Tests in memcheck

```
memcheck/tests/amd64/insn-pmovmskb       (stderr)
memcheck/tests/clientperm                (stderr)
memcheck/tests/leak-cases-full           (stderr)
memcheck/tests/leak-cases-summary        (stderr)
memcheck/tests/leak-cycle                (stderr)
memcheck/tests/lks                       (stderr)
memcheck/tests/origin5-bz2               (stderr)
memcheck/tests/signal2                   (stdout)
memcheck/tests/signal2                   (stderr)
memcheck/tests/varinfo6                  (stderr)
```

insn-pmovmskb - See issue #47  
clientperm - clang optimization issue  
leak* and lks - problem with client requests. See issue #89  
origin5-bz2/varinfo6 - missing line number. See issue #70  
signal2 - SIGSEGV in guest received by host  

# Tests in drd

```
drd/tests/atomic_var                     (stderr)
drd/tests/omp_matinv                     (stderr)
drd/tests/omp_matinv_racy                (stderr)
drd/tests/omp_prime_racy                 (stderr)
drd/tests/tc04_free_lock                 (stderr)
drd/tests/tc23_bogus_condwait            (stderr)
```

Not fully analyzed.

## x86 / GCC results

As amd64 / gcc except the following extra failures

# Tests in none

```
none/tests/fdleak_cmesg
none/tests/manytreads
none/tests/pth_self_kill_15_other
```
fdleak_cmesg - looks like a minor issue filtering open file descriptors  
manythreads - aborts after running 8192 threads, see issue #85  
th_self_kill_15_other - signal mask / exitreason problem, see issue #83

# Tests in memcheck

## x86 / clang results

39 fails. Ongoing analysis.

## Linux results

(Debug build)

```
== 783 tests, 3 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/linux/sys-preadv2_pwritev2 (stderr)
memcheck/tests/origin5-bz2               (stderr)
memcheck/tests/varinfo5                  (stderr)
```
