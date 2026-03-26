import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, 'src')

from leaklens.config import settings

print('Rules:')
for rule in settings.rules:
    print('  - ' + rule['name'] + ': ' + str(rule['loaded']))

print('\nCurrent rules:')
for rule in settings.rules:
    if rule['loaded']:
        print('  - ' + rule['name'] + ': ' + rule['regex'])
