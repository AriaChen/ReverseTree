# -*- coding: UTF-8 -*-
import os
import re
import sys
import pefile
from pygraphviz import *
import html

def getReverseFile(pe):
    command = "objdump -d " + pe + " >reverse.txt"
    os.system(command)  # 得到反汇编结果
    GetImportTable(pe)


def GetEntryPoint(pe):  # 找到程序入口点
    command = 'objdump -f ' + pe  # 得到pe文件头信息
    j = 0
    info = os.popen(command).readlines()
    for i in range(len(info[4])):
        if info[4][i] == '0':
            j = i
            break
    EntryPoint = 'Start Address: '+ info[4][j:]
    return EntryPoint


# Get Import Table
def GetImportTable(pe):
    global importTable
    importTable = {}
    pe = pefile.PE(pe)
    for importdll in pe.DIRECTORY_ENTRY_IMPORT:
        for importfun in importdll.imports:
            tempaddr = hex(importfun.address)
            importTable[str(tempaddr)] = importfun.name


def read():
    file = open("reverse.txt")
    txt = file.read()
    exp = re.compile(r'\b\w\w\b|\s+')
    t = re.sub(exp, ' ', txt)
    result = ' '.join(str(t).split())
    global filter
    filter = result.split(' ')
    for i in range(len(filter)-1):  # 去除大量int3中断，只在出现时留一个标记位
        if filter[i+1] == 'int3':
            filter[i] = 'int3'
    for j in reversed(range(len(filter))):
        if filter[j] == 'int3' and filter[j - 1] == 'int3':
            filter.pop(j)
    for c in range(len(filter)):  # 标记形如 call *%eax 指令
        if filter[c] == 'call' and filter[c + 1][0] == '*' and filter[c + 1][1] != '0':
            filter[c] = 'callq'


class Call:
    jmppoint = 0  # filter[jmppoint]内容代表起跳点，可直接定位
    jmpok = 0  # 静态链接，filter[jmpok]内容代表落地点地址字符串，jmpstr为空，需遍历找到地址
    jmpstr = ''   # 动态链接，存落地点地址字符串，jmpok为0，地址不在文件内
    retpoint = 0  # 静态链接对应函数返回点，filter[retpoint]内容为函数结尾地址，可直接定位
    argument = 0
    flag = 1  # 判断是否为函数调用图第一层结点


class If:  # 分支结构
    begin = 0
    end = 0
    flag = 1
    endFlag = 1


class While:  # 循环结构
    begin = 0
    end = 0
    flag = 1
    endFlag = 1


def FindMainFunctions():
    global arr
    arr = []
    for index in range(len(filter)):
        if filter[index] == 'callq' or (filter[index] == 'call'and filter[index + 1][0] == '*'):  # 动态链接间接寻址
            All_call = Call()
            All_call.jmppoint = index - 1  # 起跳点
            All_call.jmpstr = filter[index + 1]  # 代表落地点 e.g: All_call.jmpstr = *%edi
            arr.append(All_call)
        if filter[index] == 'call' and filter[index + 1][0] != '*':  # 直接寻址
            All_call = Call()
            All_call.jmppoint = index - 1  # 代表起跳点 e.g: filter[All_call.jmppoint] = 413cf8:
            All_call.jmpok = index + 1  # 代表落地点 e.g: filter[All_call.jmpok] = 0x413d94
            arr.append(All_call)
    for i in range(len(arr)):  # 判断ILT，更改落地点
        if arr[i].jmpok != 0:
            str = filter[arr[i].jmpok][2:8] + ':'
            for x in range(len(filter)):
                if filter[x] == str and filter[x+1] == 'jmp':  # 是否指向ILT（ILT-Incremental Link Table静态函数跳转表）
                    for n in range(len(filter)):
                        cmp = filter[x+2][2:8] + ':'
                        if filter[n] == cmp and filter[n+1] == 'jmp':
                            # 4112d5:jmp 0x4162da
                            # 4162da:jmp *0x42a178 二次跳转，动态链接
                            arr[i].jmpok = 0  # 间接寻址，存落地点即可
                            arr[i].jmpstr = filter[n + 2]

                        if filter[n] == cmp and filter[n+1] != 'jmp':
                            arr[i].jmpok = x + 2  # 更改落地点

    for i in range(len(arr)):  # 找返回点
        if arr[i].jmpok != 0:
            str = filter[arr[i].jmpok][2:8] + ':'
            for x in range(len(filter)):
                if filter[x] == str:
                    while filter[x] != 'ret' and filter[x+1] != 'int3':
                        x += 1
                    if filter[x-1] != 'bnd':
                        arr[i].retpoint = x - 1
                    if filter[x-1] == 'bnd':
                        arr[i].retpoint = x - 2  # 找到返回点即函数结束点

    for i in range(len(arr)):
        if arr[i].jmpstr != '' and importTable.has_key(arr[i].jmpstr[1:]):
            arr[i].jmpstr = importTable[arr[i].jmpstr[1:]]

    for k in range(len(arr)):
        j = 1
        count = 0
        jmppoint = arr[k].jmppoint + 1
        while filter[jmppoint - 3 * j] == 'push':
            count += 1
            j += 1
        arr[k].argument = count  # 每个函数的参数


def FindSubFunctions():
    for i in range(len(arr)):
        if arr[i].retpoint != 0 and filter[arr[i].retpoint][0] != 'j':
            # 对于每个有返回点的函数
            subarr = []  # 存函数内调用函数/分支/循环
            for j in range(len(arr)):  # 遍历arr所有call指令，找到此函数内call指令
                if filter[arr[j].jmppoint][0:6] > filter[arr[i].jmpok][2:8]\
                        and filter[arr[j].jmppoint][0:6] < filter[arr[i].retpoint][0:6]:
                    # 判断j的起跳点是否在i的落地点与返回点之间，即是否为此函数内调用的函数
                    arr[j].flag = 1  # 重置flag位
                    subarr.append(arr[j])

            for k in range(len(filter)):
                if filter[k] == filter[arr[i].jmpok][2:8] + ':':
                    start = k
            finish = arr[i].retpoint
            # 找到函数开头结尾在文件中地址

            var = 0  # 局部变量数量
            for index in range(start, finish):  # 在此函数范围内遍历找jxx指令
                if filter[index][0] == 'j':  # 存入jxx指令前后的地址
                    if filter[index-1] == 'bnd':
                        pre = index-2
                    if filter[index-1] != 'bnd':
                        pre = index-1
                    after = index+1
                    if filter[pre][0:6] < filter[after][2:8]:  # 若地址从前跳到后，则为分支结构
                        All_if = If()
                        All_if.begin = filter[pre][0:6]
                        All_if.end = filter[after][2:8]
                        subarr.append(All_if)
                    if filter[pre][0:6] > filter[after][2:8]:  # 若地址从后跳到前，则为循环结构
                        All_while = While()
                        All_while.begin = filter[after][2:8]
                        All_while.end = filter[pre][0:6]
                        subarr.append(All_while)

                if filter[index][0:3] =='mov' and filter[index+1][0] == '$' and filter[index + 1][-4:-1] == 'ebp':
                    var += 1  # 找到类似movl $0x0,-0x4(%ebp)指令，确定局部变量数量

            # var = 0
            # if filter[start + 7] == 'sub' and filter[start + 8][0] == '$':
            #     var = int(filter[start + 8][3:-5], 16)/4  # 找到函数为局部变量分配栈空间大小

            paintSubGraph(subarr, filter[arr[i].jmpok], i, arr[i].argument, var)


def paintMainGraph(arr, root):
    g = AGraph()
    # print root
    for i in range(len(arr)):
        cur = ''
        if arr[i].jmpok != 0:
            cur = 'call : ' + filter[arr[i].jmpok]  # 当前结点为i的落地点
        if arr[i].jmpok == 0:
            cur = 'call : ' + arr[i].jmpstr

        for j in range(len(arr)):
            if arr[j].jmpok != 0 and filter[arr[j].retpoint][0] != 'j':
                if filter[arr[i].jmppoint][0:6] > filter[arr[j].jmpok][2:8]\
                        and filter[arr[i].jmppoint][0:6] < filter[arr[j].retpoint][0:6]:
                    # 对于每一个i，遍历数组中每一节点j，判断i的起跳点是否在j的落地点与返回点之间
                    g.edge_attr['color'] = 'lightsteelblue'
                    g.add_edge('call : ' + filter[arr[j].jmpok], cur)
                    arr[i].flag = 0

    for i in range(len(arr)):  # 连接根节点与第一层结点
        if arr[i].flag == 1:
            g.edge_attr['color'] = 'mediumslateblue'
            g.add_edge(root, 'call : ' + filter[arr[i].jmpok])  # 根节点指向call指令落地点
    g.graph_attr['label'] = 'Main Flow Chart'
    g.graph_attr['fontname'] = 'Matura MT Script Capitals'
    g.node_attr['shape'] = 'component'
    g.node_attr['orientation'] = '5'
    g.node_attr['color'] = 'slateblue'
    g.node_attr['fontcolor'] = 'midnightblue'
    g.node_attr['fontname'] = 'Baskerville Old Face'
    g.layout(prog='dot')
    g.write('Main Flow Chart.dot')

    lines = open('Main Flow Chart.dot').readlines()  # 打开文件，读入每一行
    fp = open('Main Flow Chart.dot', 'w')  # 打开你要写的文件
    for s in lines:
        fp.write(s.replace('\n', ' '))  # 换行替换为空格
    fp.close()  # 关闭文件


    g.draw('Main Flow Chart.jpg')


def paintSubGraph(subarr, outset, order, argument, var):
    g = AGraph()
    root = 'Function Entrypoint: ' + outset
    isPaintFlag = 0
    for i in range(len(subarr)):  #对于每一个函数内结构
        cur = ''  # 当前结构头结点
        fin = ''  # 当前结构尾结点
        if isinstance(subarr[i], Call):  # 如果是call指令
            if subarr[i].jmpok != 0:
                cur = 'call : ' + filter[subarr[i].jmpok]  # 当前结点头尾均为i的落地点
            if subarr[i].jmpok == 0:
                cur = 'call : ' + subarr[i].jmpstr
            cmp = filter[subarr[i].jmppoint][0:6]
            fin = cur
        if isinstance(subarr[i], If):  # 如果是分支结构，内部连边
            g.edge_attr['color'] = 'lightsteelblue'
            g.edge_attr['fontcolor'] = 'darkslateblue'
            g.add_edge(subarr[i].begin, subarr[i].end, label="branch", style='bold')
            cur = subarr[i].begin  # 当前结点头为分支的起始点
            cmp = cur
            fin = subarr[i].end  # 当前结点尾为分支的结束点
        if isinstance(subarr[i], While):  # 如果是循环结构，内部成环
            g.edge_attr['color'] = 'mediumpurple'
            g.edge_attr['fontcolor'] = 'blueviolet'
            g.add_edge(subarr[i].begin, subarr[i].end, label="loop", style='bold', dir='both')
            g.add_edge(subarr[i].end, subarr[i].begin, style='bold', dir='both')
            cur = subarr[i].begin  # 当前结点为循环的起始点
            cmp = cur
            fin = subarr[i].end

        max = ''
        pos = 0
        for j in range(len(subarr)):
            if isinstance(subarr[j], If) or isinstance(subarr[j], While):
                if cmp > subarr[j].begin and cmp < subarr[j].end:
                    # 判断i的起跳点是否在j的落地点与返回点之间
                    if subarr[j].begin > max:  # 找到i结点对应上一层嵌套的起始位置
                        max = subarr[j].begin
                        pos = j
        if pos != 0:  #如果存在父结构，连边
            g.edge_attr['color'] = 'sandybrown'
            g.add_edge(max, cur)
            if fin != subarr[j].end:
                g.add_edge(fin, subarr[j].end)
                # subarr[pos].endFlag = 0
                if isinstance(subarr[i], If) or isinstance(subarr[i], While):
                    subarr[i].endFlag = 0  # 此时内层嵌套不再连接函数结尾
            subarr[i].flag = 0

    for i in range(len(subarr)):  # 连接根节点与第一层结点
        if subarr[i].flag == 1:
            g.edge_attr['color'] = 'sienna'
            isPaintFlag = 1
            if isinstance(subarr[i], Call):
                if subarr[i].jmpok != 0:
                    g.add_edge(root, 'call : ' + filter[subarr[i].jmpok])  # 根节点指向call指令落地点
                if subarr[i].jmpok == 0:
                    g.add_edge(root, 'call : ' + subarr[i].jmpstr)  # 根节点指向call指令落地点
            if isinstance(subarr[i], If) or isinstance(subarr[i], While):
                g.add_edge(root, subarr[i].begin)  # 根节点指向分支/循环结构起始点

    for i in range(len(subarr)):  # 连接叶子结点与ret
        g.edge_attr['color'] = 'sienna'
        if isinstance(subarr[i], If) or isinstance(subarr[i], While):
            if subarr[i].endFlag != 0:
                g.add_edge(subarr[i].end, 'ret')  # 分支/循环结构结束点指向ret

    if isPaintFlag == 0:
        g.add_edge(root, 'ret')

    g.graph_attr['label'] = 'Sub Flow Chart ' + '%d' % order + ' With ' + '%d' % argument \
                            + ' Arguments'' And ' + '%d' % var + ' Local Variables'
    g.graph_attr['fontname'] = 'Matura MT Script Capitals'
    g.graph_attr['fontcolor'] = 'saddlebrown'
    g.node_attr['shape'] = 'egg'
    g.node_attr['peripheries'] = '1'
    g.node_attr['color'] = 'rosybrown'
    g.node_attr['orientation'] = '12'
    g.node_attr['fontcolor'] = 'darkslateblue'
    g.node_attr['fontname'] = 'Comic Sans MS'
    g.edge_attr['fontname'] = 'Lucida Handwriting'
    g.layout(prog='dot')
    stringFile = '%d' % order + '-' + outset
    g.write(stringFile + '.dot')

    lines = open(stringFile + '.dot').readlines()  # 打开文件，读入每一行
    fp = open(stringFile + '.dot', 'w')
    for s in lines:
        fp.write(s.replace('\n', ' '))  # 换行替换为空格
    fp.close()  # 关闭文件

    g.draw('%d' % order + '-' + outset + '.jpg')


if __name__ == '__main__':
    getReverseFile(sys.argv[1])
    read()

    FindMainFunctions()
    paintMainGraph(arr, GetEntryPoint(sys.argv[1]))
    FindSubFunctions()
    html.Html()