
hash: hash.c hash.go
	@cc -Wall -o hc hash.c
	@go build -o hg hash.go

clean:
	@rm -f a.out hash

tags:
	@ctags *.c

wc:
	@wc -l hash.c

back backup bak:
	@cp hash.c hash.go makefile TODO .bak
