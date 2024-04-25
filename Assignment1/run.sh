#!/bin/bash

if [-d "result"]; then
    rm -rf "result"
fi

mkdir "result"
python main.py download -o result data.torrent