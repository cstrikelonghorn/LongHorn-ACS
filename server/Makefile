# ACS - ReHLDS / Metamod plugin.
#
#   make                 build the plugin (needs HLSDK + Metamod headers)
#   make HLSDK=... METAMOD=...
#   make test            build and run the engine behaviour tests (no SDK needed)
#   make clean
#
# HLDS and ReHLDS are 32-bit, so the plugin must be too. On a 64-bit Linux host that
# means the multilib toolchain: apt install g++-multilib, or dnf install glibc-devel.i686
# libstdc++-devel.i686.

HLSDK   ?= ../../hlsdk
METAMOD ?= ../../metamod/metamod

NAME     = acs
SRCDIR   = src
OBJDIR   = build
SOURCES  = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS  = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

INCLUDES = -I$(SRCDIR) \
           -I$(METAMOD) \
           -I$(HLSDK)/common \
           -I$(HLSDK)/dlls \
           -I$(HLSDK)/engine \
           -I$(HLSDK)/pm_shared \
           -I$(HLSDK)/public

# -fno-strict-aliasing is required: the HLSDK type-puns entvars fields all over, and GCC
# is entitled to miscompile that at -O2 without it.
CXXFLAGS = -m32 -O2 -fPIC -std=c++11 -fno-strict-aliasing -fvisibility=hidden \
           -Wall -Wno-unknown-pragmas -Wno-write-strings \
           -DNDEBUG $(INCLUDES)

ifeq ($(OS),Windows_NT)
    TARGET   = $(NAME)_mm.dll
    CXXFLAGS += -DWIN32 -D_WIN32
    LDFLAGS   = -m32 -shared -static-libgcc -static-libstdc++
    LDLIBS    = -lws2_32
else
    TARGET   = $(NAME)_mm_i386.so
    CXXFLAGS += -DLINUX -D_LINUX -DPOSIX \
                -Dstricmp=strcasecmp -Dstrcmpi=strcasecmp -Dstrnicmp=strncasecmp \
                -D_snprintf=snprintf -D_vsnprintf=vsnprintf
    # static libstdc++ matters here: the plugin loads into an HLDS binary that ships its
    # own ancient runtime, and a dynamic link picks up whichever happens to be resident.
    LDFLAGS   = -m32 -shared -pthread -static-libgcc -static-libstdc++
    LDLIBS    =
endif

.PHONY: all clean test check-sdk

all: check-sdk $(TARGET)

check-sdk:
	@test -f $(HLSDK)/common/const.h || \
	  (echo "HLSDK not found at $(HLSDK) - set HLSDK=/path/to/hlsdk"; exit 1)
	@test -f $(METAMOD)/meta_api.h || \
	  (echo "Metamod headers not found at $(METAMOD) - set METAMOD=/path/to/metamod/metamod"; exit 1)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)
	@echo "built $(TARGET)"

# ---------------------------------------------------------------------------
# Tests
#
# These build against tests/stubs, which are minimal fakes of the HLSDK and Metamod
# headers - enough to compile the analysis engines on a machine with no SDK checked out.
# They are NOT the real SDK and are never used by the `all` target.
#
# The tests drive synthetic usercmd streams through the real engines and assert both
# directions: cheat-shaped input must raise the rule, and human-shaped input must not.
# ---------------------------------------------------------------------------
TEST_SRC = tests/test_engines.cpp \
           $(SRCDIR)/aim.cpp $(SRCDIR)/recoil.cpp $(SRCDIR)/movement.cpp \
           $(SRCDIR)/usercmd.cpp $(SRCDIR)/behavior.cpp $(SRCDIR)/player.cpp \
           $(SRCDIR)/util.cpp

test: | $(OBJDIR)
	$(CXX) -std=c++11 -O1 -Wall -Wextra -Wno-unused-parameter \
	    -Itests/stubs -I$(SRCDIR) $(TEST_SRC) -o $(OBJDIR)/test_engines
	@$(OBJDIR)/test_engines

clean:
	rm -rf $(OBJDIR) $(TARGET)
