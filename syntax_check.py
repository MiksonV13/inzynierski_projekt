import ast

try:
    with open('test.py', 'r', encoding='utf-8') as f:
        code = f.read()
    ast.parse(code)
    print('✓ Syntax is valid')
except SyntaxError as e:
    print(f'✗ Syntax error: {e}')
    print(f'  Line {e.lineno}: {e.text}')
