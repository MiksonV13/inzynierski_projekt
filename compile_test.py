#!/usr/bin/env python
import sys

try:
    with open('test.py', 'r', encoding='utf-8') as f:
        code = f.read()
    compile(code, 'test.py', 'exec')
    print('SUCCESS: File compiles without syntax errors')
except SyntaxError as e:
    print(f'ERROR: Syntax error at line {e.lineno}: {e.msg}')
    if e.text:
        print(f'  {e.text}')
    sys.exit(1)
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
