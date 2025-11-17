#!/usr/bin/env python
import sys
import os

try:
    import test as app_module
    print("Import successful!")
    
    import tkinter as tk
    print("Tkinter available")
    
    try:
        import matplotlib
        print("Matplotlib available")
    except:
        print("Matplotlib not available - will use PIL")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
