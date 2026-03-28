import numpy as np
t = np.linspace(0, 1, 1000, endpoint=False)
signal = np.sin(2*np.pi*50*t) + 0.5*np.sin(2*np.pi*120*t)
fft_vals = np.fft.fft(signal)
freqs = np.fft.fftfreq(len(t), d=1/1000)
magnitudes = np.abs(fft_vals[:500])
peak_freq = freqs[np.argmax(magnitudes[1:])+1]
print(f"peak_freq={peak_freq:.0f}Hz mag={magnitudes.max():.0f}")
