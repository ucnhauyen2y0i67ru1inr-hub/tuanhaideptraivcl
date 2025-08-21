#!/bin/bash

# Nếu không có arg nào thì báo lỗi
if [ $# -lt 1 ]; then
  echo "Usage: $0 [url target]"
  exit 1
fi

# Tên file output sau khi compile
OUT="attack_program"

# Biên dịch âm thầm: 
# - xuất binary attack_program
# - ẩn stdout/stderr nếu biên dịch thành công
# - nếu lỗi, hiện lỗi bình thường
gcc main.c -o "$OUT" -lssl -lcrypto -lnghttp2 -lpthread >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "❌ Compile failed!"
  exit 1
fi

# Chạy chương trình với tham số URL
./"$OUT" "$1"