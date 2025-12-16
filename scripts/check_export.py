import main, os
m = main.generate_exports()
print('meta:', m)
print('exists?', os.path.exists(m['csv']))
print('cwd:', os.getcwd())
print('exports dir listing:', os.listdir('data/exports'))
