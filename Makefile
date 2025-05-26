CXX = g++
# CXXFLAGS = -std=c++11 -Wall -O2 -I/usr/local/include -I/opt/homebrew/include
# Prefer a more specific include path if known, or ensure the compiler searches defaults.
# For this project, since gmp is confirmed at /opt/homebrew/include:
CXXFLAGS = -std=c++11 -Wall -O2 -I/opt/homebrew/include

# LDFLAGS = -L/usr/local/lib -L/opt/homebrew/lib -lgmp
# Prefer a more specific lib path if known:
LDFLAGS = -L/opt/homebrew/lib -lgmp

TARGET = mh_demo
SRCS = main.cpp mh_knapsack.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS) # CXXFLAGS are used for compilation, not linking object files directly here

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean 