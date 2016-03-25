CURRENT_DIR := $(shell pwd)

ifndef OSQUERY_DIR
$(error OSQUERY_DIR is not set - please set it to the path to osquery)
endif

ifeq ($(DEBUG),true)
    OSX_VERSION := $(shell sw_vers -productVersion | cut -d. -f1-2)
    BUILD_DIRNAME := debug_darwin$(OSX_VERSION)
else
    BUILD_DIRNAME := darwin
endif

OSQUERY_BUILD := $(OSQUERY_DIR)/build/$(BUILD_DIRNAME)
OSQUERY_BINARY := $(OSQUERY_BUILD)/osquery/osqueryd
OSQUERY_SHELL := $(OSQUERY_BUILD)/osquery/osqueryi
API_QUERY := "select substr(version, 0, 6) as api from osquery_info;"
API_VERSION := $(shell $(OSQUERY_SHELL) --header=false --csv $(API_QUERY))

ifeq (,$(wildcard $(OSQUERY_BUILD)))
$(error Could not find the build directory - have you compiled osquery?)
endif

CC := gcc
CXX := g++

CPPFLAGS := \
	-g -I $(OSQUERY_DIR)/include/ \
	-DOSQUERY_BUILD_SDK_VERSION=$(API_VERSION)
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
	@echo "DEBUG         = $(DEBUG)"
	@echo "BUILD_DIRNAME = $(BUILD_DIRNAME)"
	@echo "OSQUERY_BUILD = $(OSQUERY_BUILD)"
	@echo ""
	@echo "CPPFLAGS      = $(CPPFLAGS)"
	@echo "CXXFLAGS      = $(CXXFLAGS)"
	@echo "OBJCFLAGS     = $(OBJCFLAGS)"
	@echo "LIBS          = $(LIBS)"
	@echo "LDFLAGS       = $(LDFLAGS)"
	@echo "HEADERS       = $(HEADERS)"

.PHONY: clean
clean:
	$(RM) *.o osquery_profiles.ext

.PHONY: run-osqueryd
run-osqueryd: osquery_profiles.ext extension.load
	$(OSQUERY_BINARY) \
	    --pidfile=/tmp/osqueryd.pid \
	    --db_path=/tmp/osquery.db \
	    --logger_path=/tmp \
	    --config_path=$(CURRENT_DIR)/example.conf \
	    --extensions_autoload=$(CURRENT_DIR)/extension.load \
	    --extensions_socket=/tmp/osquery.ext.sock \
	    --verbose
