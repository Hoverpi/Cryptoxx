CXX        := clang++
AR         := ar
CXXFLAGS   := -std=c++23 -Wall -Wextra -O2 -Iinclude
LDFLAGS    := -fPIC

# Paths
SRC_DIR    := src
OBJ_DIR    := build/obj
LIB_DIR    := build/lib

# Library name
LIB_NAME   := $(shell basename $(CURDIR))
LIB_STATIC := $(LIB_DIR)/lib$(LIB_NAME).a
LIB_SHARED := $(LIB_DIR)/lib$(LIB_NAME).so

# Main source
MAIN_SRC   := $(SRC_DIR)/main.cpp
MAIN_OBJ   := $(OBJ_DIR)/main.o
MAIN_BIN   := build/cryptoxx

# All library sources: all .cpp under src/ except MAIN_SRC
LIB_SRC := $(filter-out $(MAIN_SRC),$(shell find $(SRC_DIR) -name '*.cpp' -print))
# Corresponding object files in build/obj preserving subdirectories
LIB_OBJ := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(LIB_SRC))

.PHONY: all clean

all: $(LIB_STATIC) $(LIB_SHARED) $(MAIN_BIN)

# final executable: link main with library
$(MAIN_BIN): $(MAIN_OBJ) $(LIB_STATIC)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(MAIN_OBJ) -L$(LIB_DIR) -l$(LIB_NAME) -Wl,-rpath,'$$ORIGIN/lib' -o $@

# static lib from all library objects
$(LIB_STATIC): $(LIB_OBJ)
	@mkdir -p $(LIB_DIR)
	$(AR) rcs $@ $^

# shared lib from same objects
$(LIB_SHARED): $(LIB_OBJ)
	@mkdir -p $(LIB_DIR)
	$(CXX) -shared -fPIC $^ -o $@

# Build object files, preserving directories under build/obj
# $< is e.g. src/foo/bar.cpp and $@ becomes build/obj/foo/bar.o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -MMD -MP -c $< -o $@

# include auto-generated deps
-include $(LIB_OBJ:.o=.d) $(MAIN_OBJ:.o=.d)

clean:
	rm -rf build
