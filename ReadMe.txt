=======================================================================================
无实际作用，大二时弄的一个PE文件注入工具
实现将指定对话框代码注入PE文件中，实现在启动PE文件时首先必须通过一步口令验证步骤。
密码居然写死成123了~~~

实现：
RadASM  实现对话框代码，并反汇编获得所需二进制段；
根据PE文件格式将二进制段注入对应位置；

Notice：
Demo仅包含对话框二进制段注入PE文件实现；
未考虑ASR问题；

