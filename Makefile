CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2 -I/usr/local/include -I/opt/homebrew/include
LDFLAGS = -L/usr/local/lib -L/opt/homebrew/lib -lgmp

TARGET = blind_signature_demo
SRCS = blind_signature_demo.cpp rsa_blind_signature.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run 