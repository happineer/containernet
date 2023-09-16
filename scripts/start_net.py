#!/usr/bin/python3

import os
from os.path import join, isdir
import pdb

app_root_path = "./examples/automotive"
app_list = []
for item in os.listdir(app_root_path):
    item_path = join(app_root_path, item)
    if isdir(item_path):
        continue
    if item_path.endswith(".py"):
        app_list.append(item_path.split('/')[-1])

print("Containernet Application List")
app_cnt = len(app_list)
for no, app_name in zip(range(1, app_cnt+1), app_list):
    print(f"[{no}] {app_name}")

while True:
    try:
        user_input = int(input("Input the number what you want to execute >> "))
        if not(0 < user_input <= app_cnt):
            raise Exception
        app_path = join(app_root_path, app_list[user_input-1])
        print(f"Run -> {app_path}")
        os.system("sudo " + app_path)
        break
    except:
        print("Exception happen. retry again!")

print("Over..")
