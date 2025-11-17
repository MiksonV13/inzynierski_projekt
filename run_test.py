#!/usr/bin/env python
import sys
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

try:
    import test
    print("Module imported successfully")
except SyntaxError as e:
    print(f"Syntax Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
