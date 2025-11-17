import ast
try:
    with open('test.py', 'r', encoding='utf-8') as f:
        ast.parse(f.read())
    print("Syntax OK")
except SyntaxError as e:
    print(f"Syntax Error: {e}")
