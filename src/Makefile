ERLC = erlc
EBIN = ../ebin
ERLINC = ../include
ERL_FLAGS = -I$(ERLINC) +warn_unused_vars +debug_info

APP_FILE= xtea.app
APP_SRC= $(APP_FILE).src
APP_TARGET= $(EBIN)/$(APP_FILE)

include ../vsn.mk

MODULES = \
	xtea \
	xtea_test

INCLUDES =

TARGETS = $(MODULES:%=$(EBIN)/%.beam) $(APP_TARGET)

all:	$(TARGETS)

clean:
	rm -f $(TARGETS) erl_crash.dump

$(EBIN)/%.beam: %.erl
	$(ERLC) $(ERL_FLAGS) -o$(EBIN) $<


$(APP_TARGET): $(APP_SRC) ../vsn.mk
	sed -e 's;%VSN%;$(XTEA_VSN);' $< > $@


