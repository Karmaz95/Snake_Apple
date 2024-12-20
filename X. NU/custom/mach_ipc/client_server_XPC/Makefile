# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2  # Enable warnings and basic optimization
FRAMEWORKS = -framework Foundation

# Binary names and paths
SERVICE_NAME = crimson_xpc_service
CLIENT_NAME = crimson_xpc_client
INSTALL_PATH = /usr/local/bin
LAUNCHD_PATH = /Library/LaunchDaemons
PLIST_NAME = com.crimson.xpc.message_service.plist

# Source files
SERVICE_SRC = crimson_xpc_service.c
CLIENT_SRC = crimson_xpc_client.c

# Default target builds both executables
all: $(SERVICE_NAME) $(CLIENT_NAME)

# Build the XPC service
$(SERVICE_NAME): $(SERVICE_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(FRAMEWORKS)

# Build the XPC client
$(CLIENT_NAME): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(FRAMEWORKS)

# Install everything (requires sudo)
install: all
	@echo "Installing XPC service and client..."
	sudo cp $(SERVICE_NAME) $(INSTALL_PATH)/
	sudo cp $(PLIST_NAME) $(LAUNCHD_PATH)/
	sudo launchctl unload $(LAUNCHD_PATH)/$(PLIST_NAME) 2>/dev/null || true
	sudo launchctl load $(LAUNCHD_PATH)/$(PLIST_NAME)
	@echo "Installation complete"

# Clean up compiled files
clean:
	rm -f $(SERVICE_NAME) $(CLIENT_NAME)

# Uninstall everything (requires sudo)
uninstall:
	@echo "Uninstalling XPC service and client..."
	sudo launchctl unload $(LAUNCHD_PATH)/$(PLIST_NAME) 2>/dev/null || true
	sudo rm -f $(INSTALL_PATH)/$(SERVICE_NAME)
	sudo rm -f $(LAUNCHD_PATH)/$(PLIST_NAME)
	@echo "Uninstallation complete"

# Help target to show available commands
help:
	@echo "Available targets:"
	@echo "  make all        - Build both service and client"
	@echo "  make install    - Install and load the service (requires sudo)"
	@echo "  make clean      - Remove compiled files"
	@echo "  make uninstall  - Remove installed files (requires sudo)"

# Declare our phony targets (targets that don't create files)
.PHONY: all install clean uninstall help