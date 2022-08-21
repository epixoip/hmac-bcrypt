CC        := cc
CPPFLAGS  := -Iinclude/
CFLAGS    := -g3 -Og -Wall -Werror -std=c99
LDLIBS    := -lcrypto -lssl

SRC_DIR   := src
BIN_DIR   := bin

SRC       := $(wildcard $(SRC_DIR)/*.c)
OBJ       := $(SRC:$(SRC_DIR)/%.c=$(SRC_DIR)/%.o)
OUT       := $(BIN_DIR)/test

.PHONY: all clean

all: $(OUT)

$(OUT): $(OBJ) | $(BIN_DIR)
	$(CC) -o $@ $(LDFLAGS) $^ $(LDLIBS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -pv $@

clean:
	@$(RM) -rfv $(BIN_DIR) $(SRC_DIR)/*.o

-include $(OBJ:.o=.d)
