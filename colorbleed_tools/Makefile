###############################################################################
# Copyright (c) 2021-2026 David H Hoyt LLC
# ColorBleed Tooling: Unsafe Load & Store Makefile
#
# Last Updated: 1200Z 04-FEB-2026 by David Hoyt | h02332@gmail.com
# URL https://hoyt.net
#
#
# Makefile for ColorBleed XML Tools
# Research Tooling for Load & Store of ICC Profiles
# Usage: Called automatically after main build completes
#        Or manually: cd unsafe_source && make clean && make
#
#
#
# ColorBleed Warning:
# These Tools will attempt to Load & Store ICC Blobs & XML Representations
# Use with care
#
###############################################################################

# Detect build directory
BUILD_DIR ?= iccDEV/Build
REPO_ROOT ?= iccDEV

# Compiler settings
CXX ?= g++
CXXFLAGS = -O2 -DNDEBUG -std=gnu++17 -Wall
INCLUDES = -I$(REPO_ROOT)/IccProfLib \
           -I$(REPO_ROOT)/IccXML/IccLibXML \
           -I/usr/include/libxml2

# Library paths (use Build directory from normal build)
LIBDIR = $(BUILD_DIR)/IccProfLib:$(BUILD_DIR)/IccXML
LIBS = -L$(BUILD_DIR)/IccProfLib -lIccProfLib2-static \
       -L$(BUILD_DIR)/IccXML -lIccXML2-static \
       -lxml2 -lz -llzma -lm

# Static linking flags
STATIC_FLAGS = -static-libgcc -static-libstdc++

# Targets
TARGETS = iccToXml_unsafe iccFromXml_unsafe

.PHONY: all clean test install help

all: $(TARGETS)
	@echo ""
	@echo "=== Unsafe XML Tools Built ==="
	@ls -lh $(TARGETS)
	@echo ""
	@echo "ColorBleed Tooling: Unsafe Load & Store for ICC Profiles"
	@echo "Copyright (c) 2021-2026 David H Hoyt LLC"
	@echo ""

iccToXml_unsafe: IccToXml_unsafe.cpp
	@echo "Building iccToXml_unsafe..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< \
		$(BUILD_DIR)/IccProfLib/libIccProfLib2-static.a \
		$(BUILD_DIR)/IccXML/libIccXML2-static.a \
		-lxml2 -lz -llzma -lm \
		$(STATIC_FLAGS) \
		-o $@
	@chmod +x $@
	@echo "  [OK] iccToXml_unsafe built"

iccFromXml_unsafe: IccFromXml_unsafe.cpp
	@echo "Building iccFromXml_unsafe..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< \
		$(BUILD_DIR)/IccProfLib/libIccProfLib2-static.a \
		$(BUILD_DIR)/IccXML/libIccXML2-static.a \
		-lxml2 -lz -llzma -lm \
		$(STATIC_FLAGS) \
		-o $@
	@chmod +x $@
	@echo "  [OK] iccFromXml_unsafe built"

clean:
	@echo "Cleaning unsafe tools..."
	rm -f $(TARGETS)
	rm -f *.o
	rm -f test.xml roundtrip.icc
	@echo "  [OK] Clean complete"

test: all
	@echo ""
	@echo "=== Testing Unsafe Tools ==="
	@echo ""
	@echo "Test 1: iccToXml_unsafe (no args)"
	@./iccToXml_unsafe 2>&1 | head -10 || true
	@echo ""
	@echo "Test 2: iccFromXml_unsafe (no args)"
	@./iccFromXml_unsafe 2>&1 | head -10 || true
	@echo ""
	@if [ -f "$(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc" ]; then \
		echo "Test 3: Roundtrip conversion"; \
		./iccToXml_unsafe $(REPO_ROOT)/Testing/sRGB_v4_ICC_preference.icc test.xml; \
		./iccFromXml_unsafe test.xml roundtrip.icc; \
		ls -lh test.xml roundtrip.icc; \
	fi
	@echo ""
	@echo "[OK] Basic tests complete"

install: all
	@echo "Creating ColorBleed package..."
	@mkdir -p ../unsafe-tools-dist
	@cp $(TARGETS) ../unsafe-tools-dist/
	@echo "Creating README.md..."
	@cat > ../unsafe-tools-dist/README.md << 'DOCEND' ;\
# Unsafe XML Tools\n\
\n\
[ColorBleed] These tools Load & Store unsafe code for Icc Profiles.\n\
\n\
## Tools\n\
- iccToXml_unsafe: ICC to XML File\n\
- iccFromXml_unsafe: XML to ICC Blob\n\
\n\
## Build Info\n\
Built: $(shell date -u)\n\
System: $(shell uname -sm)\n\
Compiler: $(shell $(CXX) --version | head -1)\n\
\n\
## Usage\n\
./iccToXml_unsafe input.icc output.xml\n\
./iccFromXml_unsafe input.xml output.icc\n\
\n\
## ColorBleed Warning\n\
Both tools display a ColorBleed banner at startup.\n\
DOCEND
	@cd ../unsafe-tools-dist && sha256sum * > SHA256SUMS
	@cd .. && zip -r unsafe-tools-package.zip unsafe-tools-dist/
	@echo ""
	@echo "[OK] Package created: ../unsafe-tools-package.zip"
	@ls -lh ../unsafe-tools-package.zip

help:
	@echo "Unsafe XML Tools Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build both unsafe tools (default)"
	@echo "  clean    - Remove built binaries and test files"
	@echo "  test     - Build and run basic tests"
	@echo "  install  - Create distribution package"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Build iccDEV first:"
	@echo "  1. Run main build first: cd ../Build && cmake Cmake && make -j32"
	@echo "  2. Ensure libIccProfLib2-static.a and libIccXML2-static.a exist"
	@echo ""
	@echo "ColorBleed Warning:"
	@echo "These tools Load & Store unsafe code for Icc Profiles"
