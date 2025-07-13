# generate_viking_assets.py
from PIL import Image, ImageDraw, ImageFont
import os

OUTPUT_DIR = "/home/pi/cyberpet/viking_assets"
RESOLUTION = (250, 122)
COLORS = {"black": (0, 0, 0), "white": (255, 255, 255), "red": (255, 0, 0)}  # Gebruik "yellow": (255, 255, 0) voor geel-zwart-wit display
LEVELS = {
    1: {"name": "Krijger", "shapes": ["shield"]},
    2: {"name": "Berserker", "shapes": ["axe"]},
    3: {"name": "Jarl", "shapes": ["crown"]},
    4: {"name": "God", "shapes": ["lightning"]}
}

def create_viking_image(level, name, shapes):
    img = Image.new("RGB", RESOLUTION, COLORS["white"])
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 12)
    except:
        font = ImageFont.load_default()

    draw.text((10, 10), f"CyberViking: {name}", fill=COLORS["black"], font=font)
    if "shield" in shapes:
        draw.ellipse((100, 50, 150, 100), fill=COLORS["red"], outline=COLORS["black"])
        draw.text((125, 75), "S", fill=COLORS["black"], font=font)
    if "axe" in shapes:
        draw.rectangle((100, 50, 110, 80), fill=COLORS["black"])
        draw.polygon([(105, 50), (120, 40), (120, 60), (105, 50)], fill=COLORS["red"])
    if "crown" in shapes:
        draw.polygon([(100, 50), (110, 40), (120, 50), (130, 40), (140, 50)], fill=COLORS["red"])
    if "lightning" in shapes:
        draw.polygon([(100, 50), (110, 40), (105, 60), (115, 50), (110, 70)], fill=COLORS["red"])
    draw.rectangle((70, 60, 90, 100), fill=COLORS["black"])
    draw.ellipse((75, 50, 85, 60), fill=COLORS["red"])

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    img.save(f"{OUTPUT_DIR}/viking_level{level}.png")

def main():
    for level, data in LEVELS.items():
        create_viking_image(level, data["name"], data["shapes"])
    print(f"Viking-afbeeldingen opgeslagen in {OUTPUT_DIR}")

if __name__ == "__main__":
    main()