import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, 'src')

from leaklens.config import settings

print('Settings attributes:')
for attr in dir(settings):
    if not attr.startswith('_'):
        print(f'  - {attr}')

print('\nSettings contents:')
print(settings)
