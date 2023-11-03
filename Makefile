# Q = @ # quiet

ifeq ($(DEBUG), 1)
	Q =
	msg =
else
	Q = @
	msg = @printf '	%-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

# := no refernce to variable, expand once and for all
SBERF := sberf
# only assign when it's not yet defined
CFLAGS ?= -g -O2 -Werror -Wall -std=c11
# source code @ ./src
SRCDIR := src
# object file @ ./build
OBJDIR ?= build

OBJS := sberf.o
OBJS_BUILT := $(addprefix $(OBJDIR)/,$(OBJS))

all: $(SBERF) $(OBJS_BUILT)

# $@: target, $^: all the prerequisite
sberf: $(OBJS_BUILT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $^ -o $@

# this is the equivalence of OBJS_BUILT
# line symbol "|": build only once.
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

# all obj file will be stored in build directory
$(OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

clean-all:
	$(call msg,CLEANALL)
	$(Q)rm -rf $(OBJDIR) $(SBERF) $(TEST)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OBJDIR) $(SBERF)

# tests
TEST := sberf_test
TESTDIR = test
TEST_FILE := test.c

test: $(TEST)

# one liner or one filer
$(TEST): $(TESTDIR)/$(TEST_FILE)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(TESTDIR)/$(TEST_FILE) -o $(TEST)
