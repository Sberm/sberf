# Q = @ # quiet

ifeq ($(DEBUG), 1)
	Q =
	msg =
else
	Q = @
	msg = @printf '	%-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

SBERF := sberf # := no refernce to variable, expand once and for all
CFLAGS ?= -g -O2 -Werror -Wall -std=c11 # only assign when it's not yet defined
OBJDIR ?= build

OBJS := main.o
OBJS_BUILT := $(addprefix $(OBJDIR)/,$(OBJS))

all: $(SBERF) $(OBJS_BUILT)

# $@: target, $^: all the prerequisite
sberf: $(OBJS_BUILT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $^ -o $@

# this is the equivalence of OBJS_BUILT
# line symbol "|": build only once.
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

# all obj file will be stored in build directory
$(OBJDIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OBJDIR) $(SBERF)
