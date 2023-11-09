# Q = @ # quiet

ifeq ($(DEBUG), 1)
	Q =
	msg =
else
	Q = @
	msg = @printf '	%-2s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

# := no refernce to variable, expand once and for all
SBERF := sberf
# only assign when it's not yet defined
CFLAGS ?= -g -O2 -Werror -Wall -std=c11
# source code @ ./src
SRCDIR := src
# object file @ ./build
OUTPUT ?= build

CLANG ?= clang
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
             | sed 's/arm.*/arm/' \             
             | sed 's/aarch64/arm64/' \         
             | sed 's/ppc64le/powerpc/' \       
             | sed 's/mips.*/mips/' \           
             | sed 's/riscv64/riscv/' \         
             | sed 's/loongarch64/loongarch/')  
VMLINUX := foo


OBJS := sberf.o
OBJS_BUILT := $(addprefix $(OUTPUT)/,$(OBJS))


all: $(SBERF) $(OBJS_BUILT)

# $@: target, $^: all the prerequisite
sberf: $(OBJS_BUILT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $^ -o $@

# this is the equivalence of OBJS_BUILT
# line symbol "|": build only once.
$(OUTPUT)/%.o: $(SRCDIR)/%.c $(wildcard %.h) $(wildcard $(OUTPUT)/%.skel.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c (filter %.c,$^) -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,SKEL,$@)
	$(Q)(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h)| $(OUTPUT):
	$(call msg,BPF,$@)
	$(Q)(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# all obj file will be stored in build directory
$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

clean-all:
	$(call msg,CLEANALL)
	$(Q)rm -rf $(OUTPUT) $(SBERF) $(TEST)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(SBERF)

# tests
TEST := sberf_test
TESTDIR = test
TEST_FILE := test.c

test: $(TEST)

# one liner or one filer
$(TEST): $(TESTDIR)/$(TEST_FILE)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(TESTDIR)/$(TEST_FILE) -o $(TEST)
