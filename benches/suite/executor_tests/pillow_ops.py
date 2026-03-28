from PIL import Image, ImageDraw, ImageFont, ImageFilter
import io
img = Image.new("RGB", (400, 300), "white")
draw = ImageDraw.Draw(img)
draw.rectangle([50, 50, 350, 250], outline="red", width=3)
draw.ellipse([100, 80, 300, 220], fill="blue")
draw.text((150, 130), "Test", fill="white")
blurred = img.filter(ImageFilter.GaussianBlur(radius=2))
rotated = img.rotate(45, expand=True)
buf = io.BytesIO()
rotated.save(buf, format="PNG")
print(f"original={img.size} rotated={rotated.size} png={len(buf.getvalue())}")
