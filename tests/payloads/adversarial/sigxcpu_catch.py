import signal
signal.signal(signal.SIGXCPU, signal.SIG_IGN)
while True:
    pass
