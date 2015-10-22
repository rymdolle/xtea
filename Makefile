all:
	(cd src; $(MAKE))
	(cd c_src; $(MAKE))

clean:
	(cd src; $(MAKE) clean)
	(cd c_src; $(MAKE) clean)
	rm -f erl_crash.dump

test:
	erl -noshell -eval 'xtea_test:start(), halt()'
