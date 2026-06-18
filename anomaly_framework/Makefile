# Makefile -- Common Anomaly-Detection Framework
#
# Build:   make
# Run:     ./anomaly_detector -m flow -a all data.csv
# Clean:   make clean
#
# To add an algorithm, drop <name>.h and <name>_algo.c into this directory,
# add <name>_algo.o to ALGO_OBJS below, and register it in registry.c.
#
# Author: Aanya Jain

CC      = gcc
CFLAGS  = -std=gnu11 -Wall -Wextra -O2
LDLIBS  = -lm

CORE_OBJS = anomaly_detector.o framework.o registry.o
ALGO_OBJS = cusum_algo.o adwin_algo.o
OBJS      = $(CORE_OBJS) $(ALGO_OBJS)

TARGET = anomaly_detector

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

# All objects depend on the shared contract.
%.o: %.c main.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
