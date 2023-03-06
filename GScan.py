# coding:utf-8
import os
import platform

# 功能：本程序旨在为安全应急响应人员对Linux主机排查时提供便利，实现主机侧安全Checklist的自动化，用于快速主机安全点排查。


if __name__ == '__main__':
    path = os.path.dirname(os.path.abspath(__file__))
    # 导入platform库判断平台，分平台导入库
    if platform.system() == 'Windows':
        from lib.core.Windows_option import *
        windows_main(path)
    elif platform.system() == 'Linux':
        from lib.core.option import *
        main(path)

    #if '/' == (path).split()[0][0]:
    #    main(path)
    #else:
    #    windows_main(path)

