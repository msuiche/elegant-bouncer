#!/bin/bash
echo "Testing TUI abort functionality..."
echo "1. Launch TUI scan"
echo "2. Press 'q' or 'Esc' or 'Ctrl+C' to abort"
echo ""
echo "Starting in 3 seconds..."
sleep 3

# Run the TUI scan
./target/debug/elegantbouncer --scan tests/samples/ --tui

echo ""
echo "TUI exited successfully!"