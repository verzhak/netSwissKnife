
CC = gcc

SRC = main.c all.c error.c icmp.c operation.c tcp.c
LIB =

FLAGS = -Wall
FLAGS_DEBUG = -g
FLAGS_PROFILE = -p
FLAGS_RELEASE = -O2

BUILD_DIR = build
OUT = netSwissKnife
POSTFIX_DEBUG = _debug
POSTFIX_RELEASE = 

debug: clean

	mkdir -p $(BUILD_DIR)
	
	$(CC) $(FLAGS) $(FLAGS_DEBUG) $(SRC) $(LIB) -o $(BUILD_DIR)/$(OUT)$(POSTFIX_DEBUG)

profile: clean

	mkdir -p $(BUILD_DIR)

	$(CC) $(FLAGS) $(FLAGS_DEBUG) $(FLAGS_PROFILE) $(SRC) $(LIB) -o $(BUILD_DIR)/$(OUT)$(POSTFIX_DEBUG)
	
release: clean

	mkdir -p $(BUILD_DIR)

	$(CC) $(FLAGS) $(FLAGS_RELEASE) $(SRC) $(LIB) -o $(BUILD_DIR)/$(OUT)$(POSTFIX_RELEASE)

clean:

	rm -f gmon.out
	rm -f $(BUILD_DIR)/*

mrproper:

	rm -f gmon.out
	rm -Rf $(BUILD_DIR)

