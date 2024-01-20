ifeq ($(DEBUG), 1)
	Q =
	msg =
else
	Q = @
	msg = @printf '	%-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

SBERF := sberf
#CFLAGS ?= -g -O2 -Werror -std=c11
CFLAGS ?= -g -O2 -std=c11
SRCDIR := src
OUTPUT ?= build
SKEL_DIR := build_bpf
BPFTOOL := bpftool
CLANG ?= clang
BPF_LIB := libbpf.a
LLVM_STRIP ?= llvm-strip
VMLINUX ?= vmlinux/vmlinux.h

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
# bpf.c --> bpf.tmp.o --> bpf.o --> skel.h
#                                      \_ .c -> .o
#                                 	             \_ sberf

# bpf.c文件
BPF_FILE := record.bpf.c
SKEL := $(patsubst %.bpf.c, %.skel.h,$(BPF_FILE))
SKEL_BUILT := $(addprefix $(SKEL_DIR)/,$(SKEL))

# 所有.c文件的.o文件写在这里
OBJS := sberf.o cli.o record.o util.o plot.o
OBJS_BUILT := $(addprefix $(OUTPUT)/,$(OBJS))

INCLUDE := -Ivmlinux -Isrc -I/usr/include

# bpf.c --CLANG--> tmp.bpf.o --LLVM_STRIP, BPFTOOL--> bpf.o
# llvm-strip去除tmp.bpf.o中的DWARF信息
# bpftool生成bpf.o
$(SKEL_DIR)/%.bpf.o: $(SRCDIR)/%.bpf.c $(wildcard %.h) $(VMLINUX) | $(SKEL_DIR)
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
$(OUTPUT)/%.o: $(SRCDIR)/%.c $(SKEL_BUILT) $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -I$(SKEL_DIR) $(INCLUDE) -c $(filter %.c,$^) -o $@

# .o --GCC--> executable
sberf: $(OBJS_BUILT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(OBJS_BUILT) $(INCLUDE) -l:$(BPF_LIB) -lelf -lz -o $@ 

all: $(SBERF)

# all obj file will be stored in build directory
$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(SKEL_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# tests
TEST := sberf_test
TESTDIR = test
TEST_FILE := test.c

test: $(TEST)

# one liner or one filer
$(TEST): $(TESTDIR)/$(TEST_FILE)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(TESTDIR)/$(TEST_FILE) -o $(TEST)

clean-all:
	$(call msg,CLEAN-ALL)
	$(Q)rm -rf $(SKEL_DIR) $(OUTPUT) $(SBERF) $(TEST) $(TESTDIR)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(SKEL_DIR) $(OUTPUT) $(SBERF)
