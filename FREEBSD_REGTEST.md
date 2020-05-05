# regtest status for FreeBSD

** note ** run 'kldload mqueuefs' before running the tests, otherwise none/tests/mq will fail

## Tests in none

97.5% good

```
== 202 tests, 5 stderr failures, 3 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
none/tests/coolo_sigaction               (stdout)
none/tests/coolo_sigaction               (stderr)
none/tests/faultstatus                   (stderr)
none/tests/ioctl_moans                   (stderr)
none/tests/pending                       (stdout)
none/tests/pending                       (stderr)
none/tests/sigstackgrowth                (stdout)
none/tests/sigstackgrowth                (stderr)
```

Most of these are signal issues.  

none/tests/rlimit_nofile seems to behave differently when run in a console and in a terminal emulator like konsole.  

ioctl_moans - currently only have generic IOR/IOW handling. Plain IO moans.  

## Tests in memcheck

97.0% good

```
== 235 tests, 7 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/addressable               (stderr)
memcheck/tests/descr_belowsp             (stderr)
memcheck/tests/dw4                       (stderr)
memcheck/tests/gone_abrt_xml             (stderr)
memcheck/tests/sigaltstack               (stderr)
memcheck/tests/varinfo5                  (stderr)
memcheck/tests/x86/pushfpopf             (stderr)
```

addressable - signal issue  
descr_belowsp - SIGSEGV handling issue  
d4w - reading address returned by sbrk(0) is Unaddressable for the exp but only Uninitialized for FreeBSD  
gone_abrt_xml - differences in signal details  
sigaltstack - SIGSEGV handling issue  
varinfo5 - diff in source backannotation  
x86/pushfpopf - not finding name of asm function  

## Tests in massif, callgrind and cachegrind, dhat

100% good

## Tests in gdbserver_tests

85.7% good

```
== 21 tests, 2 stderr failures, 1 stdout failure, 1 stderrB failure, 3 stdoutB failures, 0 post failures ==
gdbserver_tests/mcmain_pic               (stdout)
gdbserver_tests/mcmain_pic               (stdoutB)
gdbserver_tests/mcmain_pic               (stderrB)
gdbserver_tests/mcsignopass              (stderr)
gdbserver_tests/mcsignopass              (stdoutB)
gdbserver_tests/mcsigpass                (stderr)
gdbserver_tests/mcsigpass                (stdoutB)

```

mcmain_pic - gdb complains that it can't find main_pic.c ???  
mcsignopass - guest terminating with SIGSEGV  
mcsigpass - guest getting SIGSEGV rather than SIGBUS  

## Tests in helgrind

Helgrind - 92.9% good
```
== 56 tests, 4 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
helgrind/tests/pth_cond_destroy_busy     (stderr)
helgrind/tests/tc20_verifywrap           (stderr)
helgrind/tests/tc23_bogus_condwait       (stderr)
helgrind/tests/tls_threads               (stderr)
```
pth_cond_destroy_busy - one missing race error
tc20_verifywrap - C file doesn't compile. Either need to fix the C file or disable the test.
tc23_bogus_condwait - a few extra dubious lock messages
tls_threads - don't understand the error message

## Tests in drd

DRD - 90.6% good


```
== 127 tests, 11 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
drd/tests/bar_bad                        (stderr)
drd/tests/bar_bad_xml                    (stderr)
drd/tests/concurrent_close               (stderr)
drd/tests/dlopen                         (stdout)
drd/tests/dlopen                         (stderr)
drd/tests/pth_detached3                  (stderr)
drd/tests/recursive_mutex                (stderr)
drd/tests/sigaltstack                    (stderr)
drd/tests/std_list                       (stderr)
drd/tests/tc09_bad_unlock                (stderr)
drd/tests/tc23_bogus_condwait            (stderr)
drd/tests/thread_name_xml                (stderr)
```

bar_bad - one extra error message  
bar_bad_xml - as above  
concurrent_close - runs OK standalone but not under perl regtest  
dlopen - crash  
pth_uninitialized_cond - sigbus in guest
sigaltstack - sigsegv in guest  
std_list - lots of errors related to setlocale  
drd/tests/tc09_bad_unlock - two missing error messages  
tc23_bogus_condwait - several exp files, not sure which is relevant for FreeBSD 
thread_name_xml - hard to read diffs but thread_name was crashing  


# x86 results

Not so good, around 60 fails. Ongoing analysis.

# Linux results

(Debug build)

```
== 783 tests, 3 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/linux/sys-preadv2_pwritev2 (stderr)
memcheck/tests/origin5-bz2               (stderr)
memcheck/tests/varinfo5                  (stderr)
```
