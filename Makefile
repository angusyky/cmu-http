SRC_DIR := src
BK_DIR := backend
OBJ_DIR := obj
# all src files
SRC := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(BK_DIR)/*.c)
# all objects
OBJ := $(OBJ_DIR)/y.tab.o $(OBJ_DIR)/lex.yy.o $(OBJ_DIR)/parse_http.o
# all binaries
BIN := server client
# C compiler
CC  := gcc
# C PreProcessor Flag
CPPFLAGS := -Iinclude
# compiler flags
CFLAGS   := -g
# DEPS = parse.h y.tab.h

default: all
all : server client

$(BK_DIR)/lex.yy.c: $(BK_DIR)/lexer.l
	flex -o $@ $^

$(BK_DIR)/y.tab.c: $(BK_DIR)/parser.y
	yacc -d $^ -Wconflicts-sr -Wconflicts-rr
	mv y.tab.c $@
	mv y.tab.h $(BK_DIR)/y.tab.h

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -c $< -o $@

$(OBJ_DIR)/%.o: $(BK_DIR)/%.c $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wunused-function -c $< -o $@

server: $(OBJ_DIR)/y.tab.o $(OBJ_DIR)/lex.yy.o $(OBJ_DIR)/parse_http.o $(OBJ_DIR)/responses.o $(OBJ_DIR)/server.o
	$(CC) -Werror $^ -o $@

client: $(OBJ_DIR)/y.tab.o $(OBJ_DIR)/lex.yy.o $(OBJ_DIR)/parse_http.o $(OBJ_DIR)/responses.o $(OBJ_DIR)/client.o
	$(CC) -Werror $^ -o $@

$(OBJ_DIR):
	mkdir $@

clean:
	$(RM) $(OBJ) $(BIN) $(BK_DIR)/lex.yy.c $(BK_DIR)/y.tab.*
	$(RM) -r $(OBJ_DIR)
