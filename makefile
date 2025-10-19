# Makefile for hsdev

# Set BINDIR to the directory in your PATH where you want the hsdev executable installed
#BINDIR=/home/jay/.bin/elf
## A common choice is
# BINDIR=/usr/local/bin

# Set MANDIR to where you want the manual page installed.
## For Linux, this usually works:
#MANDIR=/usr/share/man/man1

# Release date. For ronn, when making manual page
#RELDATE=2025-10-15

hsdev: hsdev.go hsdev.c
	@echo compiling...
	@go build -o hsdev hsdev.go

vet:
	@go vet hsdev.go

race:
	@go build -race -o hsdev hsdev.go

clean:
	@rm -f hsdev man1/hsdev.1.gz

# Manual Page

man: hsdev.1.ronn
	@ronn --roff --manual="User Commands" --organization="Blink Labs" --date="$(RELDATE)" hsdev.1.ronn >/dev/null 2>&1
	@gzip -f hsdev.1
	@mv hsdev.1.gz man1
	@man -l man1/hsdev.1.gz

showman:
	@man -l man1/hsdev.1.gz

install:
	@cp hsdev $(BINDIR)

installman:
	@cp man1/hsdev.1.gz $(MANDIR)

# Get a line count of the Go source files

wc:
	@wc -l *.go

# Make a local backup to the .bak directory.
# (Create .bak before running this for the first time.)

backup back bak:
	@cp -a bio.c  bio.h  hsdev.c hsdev.1.ronn *.go go.mod makefile push README.md TODO .bak
