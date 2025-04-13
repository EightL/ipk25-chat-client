CXX := g++ 
CXXFLAGS := -std=c++20 -Wall -Wextra -Werror -pedantic
LDFLAGS :=

# Debug flags - use make debug to build with debug prints
DEBUGFLAGS := -DDEBUG_PRINT

# Project files
SRCS := main.cpp client.cpp message.cpp tcp_client.cpp udp_client.cpp
OBJS := $(SRCS:.cpp=.o)
TARGET := ipk25chat-client

# Default target
all: $(TARGET)

# Debug build
debug: CXXFLAGS += $(DEBUGFLAGS)
debug: $(TARGET)

# Build target
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean