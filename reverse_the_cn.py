#!/usr/bin/env python3

import sys

cn = sys.argv[-1]

reversed_list = [item for item in cn.split(',').__reversed__()]
reversed_string = ', '.join([item for item in reversed_list])
print(reversed_string)
