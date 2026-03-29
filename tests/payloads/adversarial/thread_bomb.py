import threading
def f():
    while True:
        threading.Thread(target=f).start()
f()
