CXX = g++ 
CXXFLAGS = -std=c++20 -Wall -Wextra -O2

SOURCES = main.cpp
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = ipk25-chat

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)
