#!/bin/bash
export PYTHONPATH=./
if [ -d "result" ]; then
    rm -rf "result"
fi
mkdir "result"

commands=("1. Info" "2. Download" "3. Download_rarest_first" "4. Exit")

while true; do
    echo "Available commands:"
    for command in "${commands[@]}"; do
        echo "  $command"
    done

    read -p "Enter command (or 'exit' to quit): " command

    if [ "$command" == "4" ]; then
        echo "Exiting..."
        break
    fi

    case "$command" in
        "1")
            read -p "Enter torrent file name: " torrent_file_name
            python3 main.py info "$torrent_file_name"s
            ;;
        "2")
            read -p "Enter output directory: " output_directory
            read -p "Enter torrent file name: " torrent_file_name
            python3 main.py download -o "$output_directory" "$torrent_file_name"
            ;;
        "3")
            read -p "Enter output directory: " output_directory
            read -p "Enter torrent file name: " torrent_file_name
            python3 download_using_strategy.py download -o "$output_directory" "$torrent_file_name"
            ;;
        *)
            echo "Unknown command $command"
            ;;
    esac
done