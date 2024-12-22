ifeq ($(DEBUG),1)
	Q =
	msg = @printf '	 %-10s %s%s\n' "$(1)" "$(2)" "$(if $(3),$(3))";
	CFLAGS = -g
else
	Q = @
	msg = @printf '	 %-10s %s%s\n' "$(1)" "$(2)" "$(if $(3),$(3))";
	CFLAGS = -O2
endif

RUST_SRC := src/lib.rs

all:
	$(Q)cargo build --release
