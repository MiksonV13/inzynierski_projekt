#!/usr/bin/env python
import sys
sys.path.insert(0, '.')

try:
    from test import App
    print('Import successful')
except Exception as e:
    print(f'Import failed: {e}')
    import traceback
    traceback.print_exc()
