import psutil

def retmem():
    l = psutil.virtual_memory()
    return l.available