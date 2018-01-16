ifeq ($(ERL_EI_INCLUDE_DIR),)
ERL_ROOT_DIR = $(shell erl -eval "io:format(\"~s~n\", [code:root_dir()])" -s init stop -noshell)
ifeq ($(ERL_ROOT_DIR),)
   $(error Could not find the Erlang installation. Check to see that 'erl' is in your PATH)
endif
ERL_EI_INCLUDE_DIR = "$(ERL_ROOT_DIR)/usr/include"
ERL_EI_LIBDIR = "$(ERL_ROOT_DIR)/usr/lib"
endif

# Set Erlang-specific compile and linker flags
ERL_CFLAGS ?= -I$(ERL_EI_INCLUDE_DIR)
ERL_LDFLAGS ?= -L$(ERL_EI_LIBDIR)

CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS += -fPIC -shared -lsodium -lei

ifeq ($(CROSSCOMPILE),)
CFLAGS += -I/usr/local/include/sodium
LDFLAGS += -L/usr/local/lib

ifeq ($(shell uname),Darwin)
LDFLAGS += -Wl,-rpath /usr/local/lib -flat_namespace -undefined suppress
else
LDFLAGS += -Wl,-R/usr/local/lib
endif
endif

SRC=src/salty_nif.c
NIF=priv/salty_nif.so

all: priv $(NIF)

priv:
	mkdir -p priv

$(NIF): $(SRC)
	$(CC) -o $@ $< $(ERL_CFLAGS) $(CFLAGS) $(ERL_LDFLAGS) $(LDFLAGS)

clean:
	$(RM) $(NIF)
