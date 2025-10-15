## Overview

This is an initial pre-release version, and is not intended to be used in any manner.

This README file is automatically generated from a template, and may not apply to the contents of this repository.

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
