# Valgrind For FreeBSD

This repository contains a fork of the ongoing develoment of Valgrind on FreeBSD.

It is maintained by [Paul Floyd](https://github.com/paulfloyd).

## Objectives

The two primary objectives are

1. Get the code into a good enough state for it to be integrated into the main Valgrind repo on sourceware (git://sourceware.org/git/valgrind.git)
2. Replace the current FreeBSD ports version of Valgrind. This is currently at version 3.10 with a few backported patches.

I'm not too sure what constitutes **good enough**.

The secondary objectives are

3. Bugfixes, initially based on the Valgrind regression tests
4. Extending coverage of FreeBSD syscalls.

## Credits

I don't have a full history of everyone that has worked on this code. Obviously there is the upstream Valgrind team. When I started working on the code, it was based on the efforts of Phil Longstaff [Phil's repo](https://bitbucket.org/plongstaff/valgrind-freebsd-git.git). This stalled for a bit, and then Ed Maste [Ed's repo](https://github.com/FreeBSDFoundation/valgrind.git) took the baton. I restarted working on the code in late January 2020.

Patches (from the FreeBSD bugzilla, https://bugs.freebsd.org/bugzilla/) have been merged from Julien Nadeau, Kubilay Kocak.

Thanks to Nick Briggs for testing, analyzing and providing patches.

A fair chunk of the history can be read in [this thread](https://sourceforge.net/p/valgrind/mailman/message/36089056/) from the Valgrind mailing list.

## Building the code

The following packages shoule be installed
* autoconf
* automake
* libtool
* GNU make
* GCC (optional, but currently gives the best results)
* GNU sed (optional, but it is used in the regtest scripts)

For best results, use GCC and just follow the instructions in the regular README.  
After running configure you will need to run GNU make (gmake) rather than FreeBSD make (make).

To build with clang,

```
  configure CFLAGS="-g -O0" CC=clang
```

## Status

The code should build and execute on FreeBSD 12.1 amd64 generating both amd64 and x86 executables. 12.1 i386, 11.3 amd64 and 11.3 i386 should all also work.

The regression suite produces the following results [2020-04-23]

```
== 712 tests, 87 stderr failures, 5 stdout failures, 1 stderrB failure, 3 stdoutB failures, 0 post failures ==
```


## Bugzilla items

# FreeBSD Bugzilla

All of the patches in these items have been merged.

[Bug 234631](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=234631) - devel/valgrind: Fixes for FreeBSD 12.x support  
Several patches in this item.

[Bug 232235](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=232235) - devel/valgrind doesn't find trivial leak on head anymore, works on stable/11  
This one has been analyzed and a fix identified.

[Bug 220943](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=220943) - devel/valgrind Segmentation fault  
I haven't seen this, possibly fixed already in the repo I picked up.

[Bug 209886](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=209886) - devel/valgrind: spurious invalid free() when using aligned_alloc()  
I created a patch for this in upstream Valgrind and it seems to work on FreeBSD.

[Bug 212697](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=212697) - devel/valgrind: Please add syscalls 530 (posix_fallocate) and 531 (posix_fadvise)  
[Bug 234045](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=234045) - devel/valgrind: Add sigwait syscall support  
[Bug 235720](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=235720) - devel/valgrind: unimplemented syscall 555 (statfs)  
A few requests for missing syscalls

[Bug 228973](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=228973) - devel/valgrind: 32-bit error on FreeBSD 11.1-RELEASE-p9 #0  
[Bug 224878](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=224878) - devel/valgrind fails on i386  
Duplicate items for 32bit support  

# Valgrind Bugzilla

[Bug 208531](https://bugs.kde.org/show_bug.cgi?id=208531) - a somewhat long and disheartening read
