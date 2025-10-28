## 2025-10-28 Status

hsdev.go is the main program. It works to the point where it downloads the first 2000 block headers, then needs to create a hash of the last block header from the previous 2000 block headers retrieved from the peer. The last block header is needed to retrieve the next 2000 headers. This is similar to how it works in Bitcoin (if I understand correctly), but one of the biggest differences between Handshake and Bitcoin is that Handshake uses much more elaborate block headers. And they also use a completely different and much more complicated method of creating hashes of those block headers.

The reference I am using for the hashing function is in the hnsd code. I have extracted the part of the hnsd source code for the hashing function into hash/hash.c, and there is a corresponding (auto-translated) hash.go program in Go, that I have already integrated into hsdev.go, that currently does the same thing, but has bugs. (In the main directory, there is also hash-cxgo.go that was auto-translated by cxgo, created by the Go Team at the time when the Go compiler was written in C and they were translating it to Go. So far, I have found hash.go easier to work with.)

In both, I have created a fake block header, which is then used as input to the hashing function - header_cache() in C and HeaderCache() in Go. The resulting hash code is printed.

The header_cache() function uses three types of hashing: Blake512, SHA-3, and Blake2b, and for each, the data that is hashed is not directy from the downloaded block header, but is created from a hsk_header_t (struct) type that is a result of decoding the block header. Buffers are created from various fields of that struct, and used as the input to the hashing functions, which are not called at this level, but are deeper in the code, with a lot of opportunities for bugs before getting to them.

I am in the process of debugging the Go code. The plan is to use the faked block header struct I have created (in both hash.c and translated to Go in hash.go), along with the hash that results from passing it through the C version, and get the Go code to produce the same hash. This should be sufficient to establish that the Go code is working properly (of course, along with being able to fetch the rest of the blocks).

It will be helpful if Go packages can be located that function in the same ways that produce the same functionality of the C code, assuming the bug(s) are in the part of the code that does the three actual hashing algorithms, and not elsewhere. At least it will make the Go code simpler and more maintainable.

The method I am following is to first deduce where the problems are, then if any are in the functions that compute Blake512, SHA-3, or Blake2b, try replacing that part of the code with library functions. For example, the function hsk_sha3_process_block() in hash.c *appears* to calculate an SHA-3 hash.

I have not already tried doing that because I suspect the bugs are elsewhere, but of course I could be wrong about that.

If anyone can verify that specific functions in either hash.c or hash.go implement hashing algorithms that can be replaced by code provided by any Go package, it would help a lot!


## Overview

This is an initial pre-release version, and is not intended to be used in any manner.

## Introduction

## Quick Start

## Compiling and Installing

**hsdev** is written in Go. To compile it, you need to have Go installed. Go to [https://golang.org/dl/](https://golang.org/dl/) to download and install Go.

To compile:

```
$ go build hsdev.go
```
or if you have GNU **make** installed:
```
$ make
```
[Ignore this last part about the manual page. It is not ready yet.]

To install the manual page, copy the file **man1/hsdev.1.gz** to the directory where your manual pages are located. On Linux, this is typically **/usr/share/man/man1**.

To install **hsdev** program using **make**, edit **Makefile** to set BINDIR appropriately, then run

```
$ make install
```

To install the manual page using **make**, edit **Makefile** to set MANDIR appropriately, then run

```
$ sudo make installman
```

## Manual Page

A copy of the manual page is included here for convenience. To display it better, install it on your system and use the `man` command to view it.

```
((the manual page goes here))
```
