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

# Statically linked to libbpf for quick distribution
LIBS ?= -l:libbpf.a -lelf -lz -lpthread

# event.bpf.c
BPF_FILE_ := record event mem off_cpu lock
BPF_FILE := $(addsuffix .bpf.c,$(BPF_FILE_))
# record.skel.h
SKEL_ := $(patsubst %.bpf.c,%.skel.h,$(BPF_FILE))
SKEL := $(addprefix $(SKEL_DIR)/,$(SKEL_))

# Utilities for BPF programs
BPF_UTILS_ := bpf_util.h
BPF_UTILS := $(addprefix $(SRC_DIR)/,$(BPF_UTILS_))

# Normal object files for c programs
OBJS_ := sberf.o cli.o record.o plot.o stack.o util.o comm.o
OBJS := $(addprefix $(OBJ_DIR)/,$(OBJS_))

# Include path for normal c programs
INCLUDE := -Ivmlinux -Isrc -I/usr/include -I$(SKEL_DIR)

# Target architecture
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
| sed 's/arm.*/arm/' \
| sed 's/aarch64/arm64/' \
| sed 's/ppc64le/powerpc/' \
| sed 's/mips.*/mips/' \
| sed 's/riscv64/riscv/' \
| sed 's/loongarch64/loongarch/')

# If Makefile doesn't have this line, skel.h with be created the first time,
# got rm -rfed, and then forcefully rebuilt the second time. But the second
# time, we have the rules generated in .deps, so we good, no more rm -rf.
.PRECIOUS: $(addprefix $(SKEL_DIR)/,$(addsuffix .bpf.o,$(BPF_FILE_)))

# Dependency files path
DEPDIR := .deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d
DEPFLAGS_BPF = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.bpf.d
DEPFLAGS_TEST = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.test.d

# BPF object (after clang and bpftool gen)
$(SKEL_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(VMLINUX) $(BPF_UTILS) | $(SKEL_DIR) $(DEPDIR)
	$(call msg,BPF-OBJ,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(DEPFLAGS_BPF) \
	-Ivmlinux -I$(SRC_DIR) -c $(filter $(BPF_DIR)/%.bpf.c,$^) \
	-o $(patsubst %.bpf.o,%.tmp,$@)

	$(Q)$(LLVM_STRIP) -g $(patsubst %.bpf.o,%.tmp,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp,$@)

# BPF skeletons
$(SKEL_DIR)/%.skel.h: $(SKEL_DIR)/%.bpf.o | $(SKEL_DIR)
	$(call msg,BPF-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# BPF skeletons have to be built before objs for the first-time generation
sberf: $(SKEL) $(OBJS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(OBJS) $(INCLUDE) $(LIBS) -o $@

# Generate dependency graph while building
COMPILE_AND_GEN_DEP = $(CC) $(DEPFLAGS) $(CFLAGS) -c

# Normal .o objects for c files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPDIR)/%.d | $(OBJ_DIR) $(DEPDIR)
	$(call msg,CC,$@)
	$(Q)$(COMPILE_AND_GEN_DEP) $(INCLUDE) -o $@ $<

# Directories
$(DEPDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OBJ_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(SKEL_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Test
TEST := test_sberf
TEST_DIR := test
TEST_OBJS_ := test.o
TEST_OBJS := $(addprefix $(TEST_DIR)/,$(TEST_OBJS_))

test: $(TEST)

$(TEST): $(TEST_OBJS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(TEST_OBJS) -o $(TEST)

# Includes the default include path as well as the test directory
$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(DEPDIR)/%.test.d | $(DEPDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(DEPFLAGS_TEST) $(CFLAGS) $(INCLUDE) -I$(TEST_DIR) -c -o $@ $<

# Utilities
clean-all:
	$(call msg,CLEAN-ALL)
	$(Q)rm -rf $(SKEL_DIR) $(OBJ_DIR) $(SBERF) $(DEPDIR) $(TEST)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(SKEL_DIR) $(OBJ_DIR) $(SBERF) $(DEPDIR)

# For dependencies generation
# record.d
DEPFILES := $(OBJS_:%.o=$(DEPDIR)/%.d)
# record.bpf.d
DEPFILES += $(BPF_FILE:%.bpf.c=$(DEPDIR)/%.bpf.d)
# test.test.d
DEPFILES += $(TEST_OBJS_:%.o=$(DEPDIR)/%.test.d)

$(DEPFILES):

# Include all the generated dependencies
include $(wildcard $(DEPFILES))
