CXX        := clang++
AR         := ar
CXXFLAGS   := -std=c++23 -Wall -Wextra -O2 -Iinclude
LDFLAGS    :=

# Paths
SRC_DIR    := src
OBJ_DIR    := build/obj
LIB_DIR    := build/lib

# Files
LIB_NAME   := cryptoxx
LIB_STATIC := $(LIB_DIR)/lib$(LIB_NAME).a
LIB_SHARED := $(LIB_DIR)/lib$(LIB_NAME).so

LIB_SRC    := $(SRC_DIR)/cryptoxx.cpp
LIB_OBJ    := $(OBJ_DIR)/cryptoxx.o

MAIN_SRC   := $(SRC_DIR)/main.cpp
MAIN_OBJ   := $(OBJ_DIR)/main.o
MAIN_BIN   := build/cryptoxx

# Rules
.PHONY: all clean

all: $(MAIN_BIN)

# -- final executable --
$(MAIN_BIN): $(LIB_STATIC) $(MAIN_OBJ)
	$(CXX) $(CXXFLAGS) $(MAIN_OBJ) -L$(LIB_DIR) -l$(LIB_NAME) -Wl,-rpath,'$$ORIGIN/lib' -o $@

# ---- static library ----
$(LIB_STATIC): $(LIB_OBJ)
	mkdir -p $(LIB_DIR)
	$(AR) rcs $@ $^
	
# ---- shared library ----
$(LIB_SHARED): $(LIB_OBJ)
	mkdir -p $(LIB_DIR)
	$(CXX) -shared -fPIC $^ -o $@

# ---- object files ----
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(OBJ_DIR)/*.d

# ---- cleanup ----
clean:
	rm -rf build