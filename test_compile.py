#!/usr/bin/env python3
import sys
import ast

filepath = 'test.py'

try:
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()
    
    compile(code, filepath, 'exec')
    print(f'✓ {filepath} compiled successfully')
except SyntaxError as e:
    print(f'✗ Syntax error in {filepath}')
    print(f'  Line {e.lineno}: {e.msg}')
    if e.text:
        print(f'  {e.text.strip()}')
    sys.exit(1)
except Exception as e:
    print(f'✗ Error: {e}')
    sys.exit(1)
