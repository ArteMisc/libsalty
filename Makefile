# get information about the compilation environment
# TODO enable cross compilation
ERTS_I :=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
ERL_I :=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:lib_dir(erl_interface), "/include"])])' -s init stop -noshell)
ERL_L :=$(shell erl -eval 'io:format("~s~n", [lists:concat([code:lib_dir(erl_interface), "/lib"])])' -s init stop -noshell)
ARCH :=$(shell erl -eval 'io:format("~s~n", [lists:concat([erlang:system_info(system_architecture)])])' -s init stop -noshell)

LIBSODIUM_I = -Wall -Werror -I/usr/local/include/sodium
CFLAGS = -c -g -Wall -fPIC 
ERLANG_IFLAGS=-I$(ERTS_I) -I$(ERL_I)
ERLANG_LFLAGS =  -shared -L"$(ERL_L)" -lerl_interface -lei -L/usr/local/lib -Wl,-R/usr/local/lib -lsodium  

CC?=clang
EBIN_DIR=ebin

NIF_SRC=\
		src/salty_nif.c

all:
	mkdir -p priv/$(ARCH) &&\
		$(CC) $(CFLAGS) $(DRV_CFLAGS) $(ERLANG_IFLAGS) $(LIBSODIUM_I) src/salty_nif.c -o src/salty_nif.o # 2>&1 >/dev/null
	$(CC) src/salty_nif.o $(ERLANG_LFLAGS) -o priv/$(ARCH)/salty_nif.so
	mkdir -p  ./_build/dev/lib/salty/priv/$(ARCH)/
	cp ./priv/$(ARCH)/salty_nif.so ./_build/dev/lib/salty/priv/$(ARCH)/

clean:
	find . -name "*.o" -type f -delete
