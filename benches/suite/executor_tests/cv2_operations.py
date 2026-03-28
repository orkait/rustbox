import numpy as np
import cv2
img = np.random.randint(0, 255, (480, 640, 3), dtype=np.uint8)
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
blur = cv2.GaussianBlur(gray, (5, 5), 0)
edges = cv2.Canny(blur, 50, 150)
contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
resized = cv2.resize(img, (320, 240))
hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
print(f"gray={gray.shape} edges={np.count_nonzero(edges)} contours={len(contours)} resized={resized.shape} hsv={hsv.shape}")
