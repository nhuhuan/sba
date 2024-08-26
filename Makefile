CXX = g++
MCXXFLAGS := -g -Wall -O2 -std=c++2a -fPIC $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) #-fno-inline -fno-omit-frame-pointer
LOADLIBES := ../lift/ocaml_interface.o
LDLIBS := -L/usr/lib/ocaml -lm -ldl -lasmrun_shared -lcamlstr

HOSTSRCS = framework.cpp program.cpp function.cpp scc.cpp block.cpp insn.cpp rtl.cpp expr.cpp arithmetic.cpp state.cpp domain.cpp parser.cpp common.cpp binary.cpp arch.cpp type.cpp
TESTSRCS = main/test_jtable.cpp

SRCS = $(HOSTSRCS) $(TESTSRCS)
HOSTOBJS = $(HOSTSRCS:%.cpp=%.o)

DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.cpp = $(CXX) $(DEPFLAGS) $(MCXXFLAGS) -c
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

# Disable default rules. It seems hard to ensure that our patterns rules
# fire, instead of the default rules.
.SUFFIXES:

%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o: %.cpp cxx_flags $(DEPDIR)/%.d 
	$(COMPILE.cpp) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o: main/%.cpp cxx_flags $(DEPDIR)/%.d 
	$(COMPILE.cpp) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

.PHONY: force

cxx_flags: force
	@echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u | diff -q $@ - || echo '$(MCXXFLAGS)' | tr " " '\n' | grep -v '^$$' | sort -u  > $@

all: libsba.so test_jtable

test_jtable: $(HOSTOBJS) test_jtable.o
	$(CXX) $(MCXXFLAGS) $(LDFLAGS) -o $@ $^ $(LOADLIBES) $(LDLIBS) -L. -lsba

libsba.so: $(HOSTOBJS)
	$(CXX) $(MCXXFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $^ $(LOADLIBES) $(LDLIBS)

clean:
	rm -rf test* *.o *.so .d cxx_flags
