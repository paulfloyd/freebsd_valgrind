### regtest status for FreeBSD

All tests are on FreeBSD 12.1.

** note ** run 'kldload mqueuefs' before running the tests, otherwise none/tests/mq will fail

## amd64 / GCC results

# Tests in none

99.5% good

```
== 206 tests, 1 stderr failure, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
none/tests/rlimit_nofile                 (stderr)
```

The one failure seems to because of a socket opened by KDE/krunner. See issue #34  

# Tests in memcheck

99.2% good

```
== 252 tests, 2 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/descr_belowsp             (stderr)
memcheck/tests/gone_abrt_xml             (stderr)
```

descr_belowsp - missing info on stack guard in message. See issue #101  
gone_abrt_xml - differences in signal details. See issue #102  

## Tests in massif, callgrind and cachegrind, dhat, gdbserver_tests

# Tests in helgrind

Helgrind - 96.4% good

```
== 55 tests, 2 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
helgrind/tests/pth_cond_destroy_busy     (stderr)
helgrind/tests/tls_threads               (stderr)

```
pth_cond_destroy_busy - one missing race error  
tls_threads - a test for Linux-specific detection of tls which can't work on FreeBSD. See issue #113  

# Tests in drd

DRD - 98.4% good

```
== 126 tests, 2 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
drd/tests/dlopen                         (stdout)
drd/tests/dlopen                         (stderr)
drd/tests/std_list                       (stderr)
```

dlopen - crash, may need some hooks for dlopen. See issue #57  
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
memcheck/tests/varinfo6                  (stderr)
```

insn-pmovmskb - See issue #47  
clientperm - clang optimization issue  
leak* and lks - problem with client requests. See issue #89  
origin5-bz2/varinfo6 - missing line number. See issue #70  

# Tests in drd

```
drd/tests/atomic_var                     (stderr)
drd/tests/omp_matinv                     (stderr)
drd/tests/omp_matinv_racy                (stderr)
drd/tests/omp_prime_racy                 (stderr)
drd/tests/tc04_free_lock                 (stderr)
drd/tests/tc23_bogus_condwait            (stderr)
```

tc04_free_lock - line number differences (two are zero)  

## x86 / GCC results

As amd64 / gcc except the following extra failures

# Tests in none

```
none/tests/fdleak_cmsg
none/tests/manythreads
none/tests/pth_self_kill_15_other
```
fdleak_cmsg - looks like a minor issue filtering open file descriptors  
manythreads - aborts after running 8192 threads, see issue #85  
th_self_kill_15_other - signal mask / exitreason problem, see issue #83

# Tests in memcheck

## x86 / clang results

# Tests in none

```
== 162 tests, 2 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
none/tests/manythreads                   (stdout)
none/tests/manythreads                   (stderr)
none/tests/pth_self_kill_15_other        (stderr)

```

manythreads - fails after 8192 threads have run, see issue #85  
pth_self_kill_15_other - SIGSEGV in host, see issue #83  

# Tests in memcheck

```
== 235 tests, 12 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/dw4
memcheck/tests/leak-tree
memcheck/tests/leak_cpp_interior
memcheck/tests/varinfo5
```

memcheck/tests/dw4 - one different error message and one difference to location of error. See issue #125  
Some more clang leak/clientreq and varindo issues.

# Tests in DRD

```
== 126 tests, 12 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
drd/tests/annotate_smart_pointer         (stderr)
drd/tests/annotate_trace_memory          (stderr)
drd/tests/annotate_trace_memory_xml      (stderr)
drd/tests/concurrent_close               (stderr)
drd/tests/pth_uninitialized_cond         (stderr)
drd/tests/sigalrm                        (stderr)
```

annotate* - extra errors, see issue #126  
concurrent_close - extra errors, see issue #126  
pth_uninitialized_cond - SIGSEGV, see issue #127  
sigalrm - same as issue #122  


## Linux results

(Debug build)

```
== 783 tests, 3 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/linux/sys-preadv2_pwritev2 (stderr)
memcheck/tests/origin5-bz2               (stderr)
memcheck/tests/varinfo5                  (stderr)
```
