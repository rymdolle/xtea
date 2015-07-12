all:
	(cd src; $(MAKE))
	(cd c_src; $(MAKE))

clean:
	(cd src; $(MAKE) clean)
	(cd c_src; $(MAKE) clean)

test:
	erl -pa ebin -s xtea_test
