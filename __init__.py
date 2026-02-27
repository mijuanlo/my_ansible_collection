import sys
import os

# Deshabilitar bytecode para todos los callbacks
sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'