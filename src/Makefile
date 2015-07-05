ERLC = erlc
EBIN = ../ebin
ERLINC = ../include
ERL_FLAGS = -I$(ERLINC) +warn_unused_vars +debug_info
C_SRC=../c_src


MODULES = \
	xtea \
	xtea_test

INCLUDES =

TARGETS = $(MODULES:%=$(EBIN)/%.beam)

all:	$(TARGETS) c

clean:
	rm -f $(TARGETS) erl_crash.dump $(EBIN)/xtea.so

$(EBIN)/%.beam: %.erl
	$(ERLC) $(ERL_FLAGS) -o$(EBIN) $<

c:
	gcc -fPIC -shared -o $(EBIN)/xtea.so $(C_SRC)/xtea_nif.c -I $(ERL_ROOT)usr/include/
