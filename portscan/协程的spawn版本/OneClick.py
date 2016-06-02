import os
import re

def gettasks():
    rootdir = os.getcwd()
    tasks = []
    for parentname ,dirname,filenames in os.walk(rootdir):
        for filename in filenames:
            input = re.findall(r".*txt",str(filename))
            if len(input)>0:
                tasks.append(input[0])
    return tasks

def run():
    Tasks = gettasks()
    for task in Tasks:
        task = str(task)
        command = "python Scan.py "+task
        output = os.system(command)

run()

