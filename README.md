# win32asmInjectTool
开发语言：win32asm
;界面是windows sdk，不需要额外支持
;程序使用 xedParse 汇编文本内容，将汇编后的二进制 以远线程方式注入目标进程

程序编译选项：
ml /c /coff x32InjectCode.asm
rc x32InjectCode.rc
link /subsystem:windows x32InjectCode.obj x32InjectCode.res
