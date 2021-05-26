# Search libc function offset

## LibcSearcherEx的修改内容

随着学习的深入，我发现**LibcSearcher**实际上已经不适用于现在的一些题目（例如：需要爆破的题目），已经被大多数人所抛弃转而使用pwntools的ELF，或者直接使用偏移值。

但是基于个人早期做题都是用**LibcSearcher**，对此有些情怀，同时因为直接使用偏移值对于阅读者来说不友好，移植也不方便。

所以我以以上想法作为初衷，对原版的**LibcSearcher**进行了一些修改，力求让使用者可以快速的做题，对本脚本有修改意见的也可以提出，如果我有空一定会对其进行改进，**同时觉得实用的麻烦点个Star吧~**

当前我对其的大概可以概括为以下几点

### 1.提升搜索速度

在原版的**LibcSearcher**中使用的是正则进行匹配地址，实际测试中效率比较低，现在改成了逐行比对的形式，搜索效率提升四倍左右，相对于原本版本在使用过程中会有明显的卡顿，现在的版本流畅无比，与直接使用ELF('./libc')来定位到libc的使用时长差不多，如果你使用ELF只为了symbols的数据，不妨试试直接使用本模块。

### 2.设置默认Libc版本

在实际使用过程中，如果exp中存在爆破等操作，而且恰巧搜索出来多个结果，那么此时每次爆破都需要手动来选择使用的Libc，现在修改后的版本，可以通过传参来固定选择的结果。

```python
from LibcSearcher import *
#第三个参数，如果有多个Libc被匹配，默认选择第一个来使用
obj = LibcSearcher("fgets", 0x7ff39014bd90, 1)
```
### 3.自动计算libc_base

在实际使用过程中，每次都会计算一个libc_base，然后再用libc_base + libc.dump('xxx')的形式来使用，在现在的使用中，只要选择匹配了libc文件后，就会自动计算出libc_base，并且使用libc.sym或者libc.symbols计算出来的地址都是带偏移的。但是为了兼容旧版，所以使用dump函数返回的地址不带偏移。

使用sym和symbols也是为了快速将libc = ELF('./libc')，这种写法的脚本快速移植。

```python
from LibcSearcher import *
obj = LibcSearcher("fgets", 0x7ff39014bd90, 1)
print("[+]libc_base: " + hex(obj.address))
print("[+]/bin/sh offset: " + hex(obj.sym["str_bin_sh"]))
```
### 4.自动计算one_gadget

使用这个功能的前提是机子上已经安装了one_gadget，以list形式返回one_gadget，并且会带有偏移。

```python
from LibcSearcher import *
obj = LibcSearcher("fgets", 0x7ff39014bd90, 1)
print("[+]one_gadget: " + str([hex(i) for i in obj.one_gadget]))
```
### 5.新增字段

为了便于使用，新增了以下字段。

* sym/symbols，字典，计算带libc_base的符号，便于移植脚本
* libc_file，字符串，当前匹配的libc文件位置
* address，数值，当前匹配的libc文件基址

## 原版LibcSearcher介绍

### 简介

这是针对CTF比赛所做的小工具，在泄露了Libc中的某一个函数地址后，常常为不知道对方所使用的操作系统及libc的版本而苦恼，常规方法就是挨个把常见的Libc.so从系统里拿出来，与泄露的地址对比一下最后12位。

为了不在这一块浪费太多生命，写了几行代码，方便以后重用。

这里用了[libc-database](https://github.com/niklasb/libc-database?fileGuid=KjT9TWKjv8vhRvxh)的数据库。

### 安装

```plain
git clone https://github.com/lieanu/LibcSearcher.git
cd LibcSearcher
python setup.py develop
```
### LibcSearcherEx安装（推荐）

```plain
git clone https://github.com/wjhwjhn/LibcSearcher.git
cd LibcSearcher
python setup.py develop
```
### 示例

```python
from LibcSearcher import *
#第二个参数，为已泄露的实际地址,或最后12位(比如：d90)，int类型
obj = LibcSearcher("fgets", 0X7ff39014bd90)
obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
obj.dump("__libc_start_main_ret")    
```
如果遇到返回多个libc版本库的情况，可以通过`add_condition(leaked_func, leaked_address)`来添加限制条件，也可以手工选择其中一个libc版本（如果你确定的话）。

