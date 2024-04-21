#!/bin/bash

# Set the path to the Python script
PYTHON_SCRIPT="main2.py"

# Set values for variables
bencoded_value="your_bencoded_value_here"
torrent_file_name="sample.torrent"
peer_ip_with_port="your_peer_ip_with_port_here"
output_directory="sample.txt"
piece="0"

# Run the Python script with appropriate arguments based on the command
command="$1"
case "$command" in
    decode)
        python3 "$PYTHON_SCRIPT" decode "$bencoded_value"
        ;;
    info|peers|handshake)
        python3 "$PYTHON_SCRIPT" "$command" "$torrent_file_name"
        ;;
    download)
        python3 "$PYTHON_SCRIPT" "$command" -o "$output_directory" "$torrent_file_name" "$piece"
        ;;
    download_rarest)
        python3 "$PYTHON_SCRIPT" "$command" -o "$output_directory" "$torrent_file_name"
        ;;
    *)
        echo "Unknown command: $command" >&2
        exit 1
        ;;
esac
