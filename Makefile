ifeq ($(DEBUG), 1)
	Q =
	msg =
	CFLAGS = -g -std=c11
else
	Q = @
	msg = @printf '	%-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
	CFLAGS = -O2 -std=c11
endif

SBERF := sberf
SRCDIR := src
OUTPUT ?= build
SKEL_DIR := build_bpf
BPFTOOL := bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX ?= vmlinux/vmlinux.h
LIBS ?= -l:libbpf.a -lelf -lz 
UTILS_H := util.h bpf_util.h sym.h
UTILS := $(addprefix $(SRCDIR)/,$(UTILS_H))

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
| sed 's/arm.*/arm/' \
| sed 's/aarch64/arm64/' \
| sed 's/ppc64le/powerpc/' \
| sed 's/mips.*/mips/' \
| sed 's/riscv64/riscv/' \
| sed 's/loongarch64/loongarch/')

# *.bpf.c: eBPF c文件
# *.bpf.o: clang和bpftool生成的eBPF目标文件*.bpf.o(在build_bpf文件夹中)
# *.skel.h: 使用*.bpf.o, 通过bpftool生成的skeleton header, 如sberf.skel.h(在build_bpf文件夹中)
# *.c: 普通c文件，通过include skeleton header调用eBPF
# *.o: 通过cc, 将所有常规.o文件链接，生成sberf可执行文件
#
# bpf.c --Clang--> bpf.tmp.o --bpftool--> bpf.o --bpftool--> skel.h
#                                                               \_ .c --gcc--> .o
#                                                                               \_ sberf

# bpf.c文件
BPF_FILE_ := record event mem off_cpu
BPF_FILE := $(addsuffix .bpf.c, $(BPF_FILE_))
SKEL := $(patsubst %.bpf.c, %.skel.h,$(BPF_FILE))
SKEL_BUILT := $(addprefix $(SKEL_DIR)/,$(SKEL))

# 所有.c文件的.o文件写在这里
OBJS := sberf.o cli.o record.o plot.o stack.o 
OBJS_BUILT := $(addprefix $(OUTPUT)/,$(OBJS))

INCLUDE := -Ivmlinux -Isrc -I/usr/include

# bpf.c --CLANG--> tmp.bpf.o --LLVM_STRIP, BPFTOOL--> bpf.o
# llvm-strip去除tmp.bpf.o中的DWARF信息
# bpftool生成bpf.o
$(SKEL_DIR)/%.bpf.o: $(SRCDIR)/%.bpf.c $(SRCDIR)/$(wildcard %.h) $(VMLINUX) $(UTILS) | $(SKEL_DIR)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-Ivmlinux -c $(filter $(SRCDIR)/%.bpf.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(LLVM_STRIP) -g $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# bpf.o --BPFTOOL--> .skel.h
.PRECIOUS: $(SKEL_DIR)/%.skel.h # 编译完了不删掉skel.h
$(SKEL_DIR)/%.skel.h: $(SKEL_DIR)/%.bpf.o | $(SKEL_DIR)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# .c --GCC--> .o
$(OUTPUT)/%.o: $(SRCDIR)/%.c $(SKEL_BUILT) $(SRCDIR)/$(wildcard %.h) $(UTILS) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -I$(SKEL_DIR) $(INCLUDE) -c $(filter %.c,$^) -o $@

# .o --GCC--> executable
sberf: $(OBJS_BUILT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(OBJS_BUILT) $(INCLUDE) $(LIBS) -o $@ 

all: $(SBERF)

# all obj file will be stored in build directory
$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(SKEL_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# tests
TEST := tsb
TESTDIR = test
TEST_OBJS := test.o 
TEST_OBJS_FULL := $(addprefix $(TESTDIR)/,$(TEST_OBJS))
TO_TEST := sym.h

test: $(TEST)

$(TESTDIR)/%.o: $(TESTDIR)/%.c $(SRCDIR)/$(TO_TEST)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDE) -c $(filter %.c,$^) -o $@

$(TEST): $(TESTDIR)/$(TEST_OBJS)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(TEST_OBJS_FULL) -o $(TEST)

clean-all:
	$(call msg,CLEAN-ALL)
	$(Q)rm -rf $(SKEL_DIR) $(OUTPUT) $(SBERF) $(TEST)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(SKEL_DIR) $(OUTPUT) $(SBERF)
