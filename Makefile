ifeq ($(DEBUG),1)
	Q =
	msg = @printf '	 %-10s %s%s\n' "$(1)" "$(2)" "$(if $(3),$(3))";
	CFLAGS = -g
else
	Q = @
	msg = @printf '	 %-10s %s%s\n' "$(1)" "$(2)" "$(if $(3),$(3))";
	CFLAGS = -O2
endif

SRC_DIR := src
BPF_DIR := src/bpf
OBJ_DIR := build
SKEL_DIR := build_bpf

SBERF := sberf
BPFTOOL := bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX ?= vmlinux/vmlinux.h
LIBS ?= -l:libbpf.a -lelf -lz -lpthread

BPF_FILE_ := record event mem off_cpu lock
BPF_FILE := $(addsuffix .bpf.c,$(BPF_FILE_))
SKEL_ := $(patsubst %.bpf.c,%.skel.h,$(BPF_FILE))
SKEL := $(addprefix $(SKEL_DIR)/,$(SKEL_))

UTILS_ := util.h bpf_util.h sym.h
UTILS := $(addprefix $(SRC_DIR)/,$(UTILS_))

OBJS_ := sberf.o cli.o record.o plot.o stack.o util.o comm.o
OBJS := $(addprefix $(OBJ_DIR)/,$(OBJS_))

INCLUDE := -Ivmlinux -Isrc -I/usr/include

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
| sed 's/arm.*/arm/' \
| sed 's/aarch64/arm64/' \
| sed 's/ppc64le/powerpc/' \
| sed 's/mips.*/mips/' \
| sed 's/riscv64/riscv/' \
| sed 's/loongarch64/loongarch/')

# bpf
$(SKEL_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(SRC_DIR)/$(wildcard %.h) $(VMLINUX) $(UTILS) | $(SKEL_DIR)
	$(call msg,"BPF-OBJ",$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-Ivmlinux -I$(SRC_DIR) -c $(filter $(BPF_DIR)/%.bpf.c,$^) \
		-o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

	$(Q)$(LLVM_STRIP) -g $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

$(SKEL_DIR)/%.skel.h: $(SKEL_DIR)/%.bpf.o | $(SKEL_DIR)
	$(call msg,BPF-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# c
sberf: $(OBJS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(OBJS) $(INCLUDE) $(LIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(SKEL) $(SRC_DIR)/$(wildcard %.h) $(UTILS) | $(OBJ_DIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -I$(SKEL_DIR) $(INCLUDE) -c $(filter %.c,$^) -o $@

# directories
$(OBJ_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(SKEL_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# tests
TEST := tsb
TEST_DIR = test
TEST_OBJS_ = test.o
TEST_OBJS := $(addprefix $(TEST_DIR)/,$(TEST_OBJS_))
TO_TEST := sym.h

test: $(TEST)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(SRC_DIR)/$(TO_TEST)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDE) -c $(filter %.c,$^) -o $@

$(TEST_DIR): $(TEST_OBJS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(TEST_OBJS) -o $(TEST)

clean-all:
	$(call msg,CLEAN-ALL)
	$(Q)rm -rf $(SKEL_DIR) $(OBJ_DIR) $(SBERF) $(TEST)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(SKEL_DIR) $(OBJ_DIR) $(SBERF)
