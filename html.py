# -*- coding: UTF-8 -*-

import sys
import os
import re
import HTMLParser


def replace1(str):
    str = str.replace('\\', '\\\\')
    return str

def replace(str):
    str = str.replace('.dot', '')
    return str

def Html():
    items = os.listdir(".")
    newlist = []
    for names in items:
        if names.endswith(".dot"):
            newlist.append(names)

    for i in range(len(newlist)):
        graph = open(newlist[i])
        txt = graph.read()
        srcPath = newlist[i]
        path = os.path.abspath(srcPath)
        # 路径

        # 基础网页
        graph = open('model.html', 'r+')
        txt = graph.read()
        # print txt
        # 赋值给每一个网页  新建一个html

        f = open(str(replace(newlist[i])) + '.html', 'w+')
        f.write(txt)

        f = open(str(replace(newlist[i])) + '.html', 'w+')
        lines = f.readlines()
        lines[34] += '"' + str(replace1(path)) + '"'

        f = open(str(replace(newlist[i])) + '.html', 'w+')
        f.writelines(lines)
        f.close()








