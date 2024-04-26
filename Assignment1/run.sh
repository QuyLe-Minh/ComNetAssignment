#!/bin/bash
export PYTHONPATH=./
if [ -d "result" ]; then
    rm -rf "result"
fi
mkdir "result"

commands=("info" "download" "download_rarest_first")

# Print the list of commands
echo "Available commands:"
for command in "${commands[@]}"; do
    echo "  $command"
done

read -p "Enter command: " command

python server.py
python client.py

if [ "$command" == "info" ]; then
    read -p "Enter torrent file name: " torrent_file_name
    python main.py info "$torrent_file_name"
elif [ "$command" == "download" ]; then
    read -p "Enter output directory: " output_directory
    read -p "Enter torrent file name: " torrent_file_name
    python main.py download -o "$output_directory" "$torrent_file_name"
elif [ "$command" == "download_rarest_first" ]; then
    read -p "Enter output directory: " output_directory
    read -p "Enter torrent file name: " torrent_file_name    
    python download_using_trategy.py download -o "$output_directory" "$torrent_file_name"
else
    echo "Unknown command $command"
fi