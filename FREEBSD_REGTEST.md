# regtest status for FreeBSD

** note ** run 'kldload mqueuefs' before running the tests, otherwise none/tests/mq will fail

## Tests in none

96.1% good

```
== 203 tests, 7 stderr failures, 4 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
none/tests/async-sigs                    (stderr)
none/tests/bug234814                     (stdout)
none/tests/bug234814                     (stderr)
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

ioctl_moans - currently only have generic IOR/IOW handling. Plain IO moans.  

## Tests in memcheck

96.1% good

```
== 231 tests, 9 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/addressable               (stderr)
memcheck/tests/descr_belowsp             (stderr)
memcheck/tests/dw4                       (stderr)
memcheck/tests/gone_abrt_xml             (stderr)
memcheck/tests/reach_thread_register     (stderr)
memcheck/tests/sigaltstack               (stderr)
memcheck/tests/varinfo5                  (stderr)
memcheck/tests/x86/pushfpopf             (stderr)

```

addressable - signal issue  
descr_belowsp - SIGSEGV handling issue  
d4w - reading address returned by sbrk(0) is Unaddressable for the exp but only Uninitialized for FreeBSD  
gone_abrt_xml - differences in signal details  
reach_thread_register - false positive leak  
sigaltstack - SIGSEGV handling issue  
varinfo5 - diff in source backannotation  
x86/pushfpopf - not finding name of asm function  

## Tests in massif

100% good

== 37 tests, 0 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==

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

## Tests in drd and helgrind

I have fixed a few issues (wrong redir signatures for Helgrind, semaphore functions in libc not libthr). But there are still a load of errors.

DRD - 46.1% good
Helgrind - 28.6% good


```
-- Finished tests in drd/tests -----------------------------------------

== 128 tests, 69 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==


-- Finished tests in helgrind/tests ------------------------------------

== 56 tests, 40 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==


```

Few analyzed, but I see many errors 'detected' in the pthread functions


# Tests in dhat

100% good

```
== 6 tests, 0 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
```

# x86 results

Not so good  
628 tests, 183 stderr failures, 15 stdout failures, 5 post faulures  
Memcheck:  
memcheck/tests/leak-segv-jmp  
memcheck/tests/leak_cpp_interior  
memcheck/tests/post-syscall  
memcheck/tests/sendmsg  
memcheck/tests/supp_unknown  
memcheck/tests/test-plo-no  

Massif:  
Several new fails  

None:  
Also several new fails  

# Linux results

(Debug build)

```
== 783 tests, 3 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/linux/sys-preadv2_pwritev2 (stderr)
memcheck/tests/origin5-bz2               (stderr)
memcheck/tests/varinfo5                  (stderr)
```
