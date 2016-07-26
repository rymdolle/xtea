all:
	rebar compile

clean:
	rebar clean

test:
	erl -noshell -eval 'xtea_test:start(), halt()'
