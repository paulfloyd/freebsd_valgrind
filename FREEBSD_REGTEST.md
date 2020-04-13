# regtest status for FreeBSD

** note ** run 'kldload mqueuefs' before running the tests, otherwise none/tests/mq will fail

## Tests in none

93.6% good


```

pselect_alarm hangs. Valgrind says that it is terminating, but the last thread doesn't die.

== 204 tests, 11 stderr failures, 5 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
none/tests/amd64/sse4-64                 (stdout)
none/tests/async-sigs                    (stderr)
none/tests/bug234814                     (stdout)
none/tests/bug234814                     (stderr)
none/tests/coolo_sigaction               (stdout)
none/tests/coolo_sigaction               (stderr)
none/tests/faultstatus                   (stderr)
none/tests/ioctl_moans                   (stderr)
none/tests/nocwd                         (stderr)
none/tests/pending                       (stdout)
none/tests/pending                       (stderr)
none/tests/procfs-non-linux              (stderr)
none/tests/rlimit_nofile                 (stderr)
none/tests/scripts/bug231357             (stderr)
none/tests/sigstackgrowth                (stdout)
none/tests/sigstackgrowth                (stderr)
```

Most of these are signal issues.

amd64/sse4-64 - floating point issues
nocwd and scripts/bug231357 - fail to unlink gdb pipes
rlimit_nofile - problem with setting errno
procfs-non-linux - not applicable and needs to be disabled
ioctl_moans - currently only have generic IOR/IOW handling. Plain IO moans.

## Tests in memcheck

93.9% good

```
== 231 tests, 14 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
memcheck/tests/addressable               (stderr)
memcheck/tests/descr_belowsp             (stderr)
memcheck/tests/dw4                       (stderr)
memcheck/tests/gone_abrt_xml             (stderr)
memcheck/tests/leak-segv-jmp             (stderr)
memcheck/tests/leak_cpp_interior         (stderr)
memcheck/tests/origin5-bz2               (stderr)
memcheck/tests/reach_thread_register     (stderr)
memcheck/tests/sigaltstack               (stderr)
memcheck/tests/sigkill                   (stderr)
memcheck/tests/supponlyobj               (stderr)
memcheck/tests/test-plo-no               (stderr)
memcheck/tests/varinfo5                  (stderr)
memcheck/tests/x86/pushfpopf             (stderr)

```

Mostly not analyzed.

addressable - looks like a filtering issue

## Tests in gdbserver_tests

71.4% good

```
== 21 tests, 5 stderr failures, 1 stdout failure, 2 stderrB failures, 3 stdoutB failures, 0 post failures ==
gdbserver_tests/hginfo                   (stderr)
gdbserver_tests/mcinfcallWSRU            (stderrB)
gdbserver_tests/mcmain_pic               (stdout)
gdbserver_tests/mcmain_pic               (stderr)
gdbserver_tests/mcmain_pic               (stdoutB)
gdbserver_tests/mcmain_pic               (stderrB)
gdbserver_tests/mcsignopass              (stderr)
gdbserver_tests/mcsignopass              (stdoutB)
gdbserver_tests/mcsigpass                (stderr)
gdbserver_tests/mcsigpass                (stdoutB)
gdbserver_tests/nlgone_abrt              (stderr)

```

Mostly not analyed.

mcinfcallWSRU - looks like a filter issue

## Tests in drd and helgrind

I have fixed a few issues (wrong redir signatures for Helgrind, semaphore functions in libc not libthr). But there are still a load of errors.

DRD - 46.1% good
Helgrind - 23.2% good


```
-- Finished tests in drd/tests -----------------------------------------

== 128 tests, 69 stderr failures, 1 stdout failure, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==


-- Finished tests in helgrind/tests ------------------------------------

== 56 tests, 43 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==


```

Few analyzed, but I see many errors 'detected' in the pthread functions


# Tests in dhat

100% good

```
== 6 tests, 0 stderr failures, 0 stdout failures, 0 stderrB failures, 0 stdoutB failures, 0 post failures ==
```
