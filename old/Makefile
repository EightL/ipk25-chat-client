# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -Werror -pedantic
LDFLAGS := 

# Project files
SRCS := main.cpp
OBJS := $(SRCS:.cpp=.o)
TARGET := ipk25-chat

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean