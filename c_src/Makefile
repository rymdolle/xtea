PRIV=../priv

INCLUDES =

TARGETS = $(PRIV)/xtea.so

all:	$(TARGETS)

clean:
	rm -f $(TARGETS) 

$(PRIV)/xtea.so: xtea_nif.c
	gcc -fPIC -shared -o $(PRIV)/xtea.so xtea_nif.c -I $(ERL_ROOT)/usr/include

