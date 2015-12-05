CURRENT_DIR := $(shell pwd)

OSQUERY_DIR := ~/repos/osquery
OSQUERY_BUILD := $(OSQUERY_DIR)/build/debug_darwin10.11
OSQUERY_BINARY := $(OSQUERY_BUILD)/osquery/osqueryd

CC := gcc
CXX := g++

CPPFLAGS := -g -I $(OSQUERY_DIR)/include/
CFLAGS :=
CXXFLAGS := -std=c++11

LIBS := \
    -lgflags \
    -lglog \
    -lthrift \
    -lrocksdb \
    -lboost_system \
    -lboost_filesystem \
    -lboost_thread-mt \
    -losquery \
    -lobjc
FRAMEWORKS := -framework Foundation
LDFLAGS := \
    -L $(OSQUERY_BUILD)/osquery/ \
    -L $(OSQUERY_BUILD)/libglog-prefix/src/libglog-build/.libs/ \
    $(FRAMEWORKS) \
    $(LIBS)

HEADERS := \
    $(shell find . -name '*.hpp') \
    $(shell find . -name '*.h')

##################################################
## TARGETS

all: osquery_profiles.ext extension.load

osquery_profiles.ext: osquery_profiles.o
	$(CXX) -o $@ $(LDFLAGS) $^

extension.load:
	echo "$(CURRENT_DIR)/osquery_profiles.ext" > $@


##################################################
## OBJECTS

osquery_profiles.o: osquery_profiles.cpp $(HEADERS)
	$(CXX) -c -o $@ $(CPPFLAGS) $(CXXFLAGS) $<


##################################################
## DEBUGGING & UTILITY

.PHONY: env
env:
	@echo "CPPFLAGS     = $(CPPFLAGS)"
	@echo "CXXFLAGS     = $(CXXFLAGS)"
	@echo "OBJCFLAGS    = $(OBJCFLAGS)"
	@echo "LIBS         = $(LIBS)"
	@echo "LDFLAGS      = $(LDFLAGS)"
	@echo "HEADERS      = $(HEADERS)"

.PHONY: clean
clean:
	$(RM) *.o osquery_profiles.ext

.PHONY: run-osqueryd
run-osqueryd: osquery_profiles.ext extension.load
	$(OSQUERY_BINARY) \
	    --pidfile=/tmp/osqueryd.pid \
	    --db_path=/tmp/osquery.db \
	    --logger_path=/tmp \
	    --extensions_autoload=$(CURRENT_DIR)/extension.load \
	    --extensions_socket=/tmp/osquery.ext.sock \
	    --verbose
