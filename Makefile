# Makefile for FortressFS static build

CXX = g++
CXXFLAGS = -static -static-libgcc -static-libstdc++ -Iinclude
LDFLAGS = -lssl -lcrypto
SRC_DIR = src
APP_DIR = app
TARGET = fortresses

# Collect all .cpp files
SRCS = $(wildcard $(SRC_DIR)/*.cpp) $(APP_DIR)/main.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGET) $(SRC_DIR)/*.o $(APP_DIR)/*.o
