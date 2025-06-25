import os
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext
from PIL import Image, ImageTk

from ipwhois import IPWhois
import folium
from geopy.geocoders import Nominatim
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# -------- Core GARS Logic --------

def map_entity_location(entity):
    ip = socket.gethostbyname(entity) if not entity.replace(".", "").isdigit() else entity
    results = IPWhois(ip).lookup_rdap()
    return {
        "ip": ip,
        "asn": results.get("asn"),
        "country": results.get("asn_country_code"),
        "org": results.get("asn_description"),
        "cidr": results.get("asn_cidr")
    }

def calculate_geo_risk_score(entity):
    try:
        loc = map_entity_location(entity)
        code, asn = loc.get("country", "XX"), loc.get("asn", "NA")
        score = {
            "instability": {"GB": 0.2, "RU": 0.8, "US": 0.4}.get(code.upper(), 0.5),
            "threat_trends": {"GB": 0.6, "IN": 0.7, "CN": 0.9}.get(code.upper(), 0.5),
            "compliance": {"EU": 0.9, "US": 0.6, "IN": 0.5}.get(code.upper(), 0.4),
            "infra_exposure": 0.9 if asn in ["AS12345", "AS45678"] else 0.3
        }
        score["aggregated"] = round(sum(score.values()) / len(score), 3)
        return {"entity": entity, "location": loc, "risk_metrics": score}
    except Exception as e:
        return {"error": str(e)}

def generate_static_map(loc, html_file="gars_map.html", png_file="gars_map.png"):
    code, ip, org = loc.get("country"), loc.get("ip"), loc.get("org")
    geo = Nominatim(user_agent="gars").geocode(code)
    if not geo:
        raise ValueError("Geolocation failed.")

    fmap = folium.Map(location=[geo.latitude, geo.longitude], zoom_start=4)
    folium.Marker([geo.latitude, geo.longitude],
                  tooltip=f"{code} - {ip}", popup=f"Org: {org}").add_to(fmap)
    fmap.save(html_file)

    # Setup headless browser
    options = Options()
    options.headless = True
    options.add_argument("--window-size=800,600")

    driver = webdriver.Chrome(options=options)
    driver.get(f"file:///{os.path.abspath(html_file)}")
    driver.implicitly_wait(5)
    driver.save_screenshot(png_file)
    driver.quit()

    return png_file

# -------- GUI Code --------

root = tk.Tk()
root.title("GARS – CTI Risk Analyzer")
root.geometry("1100x620")

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

left = ttk.Frame(main_frame)
left.pack(side=tk.LEFT, fill=tk.Y)

right = ttk.LabelFrame(main_frame, text="📍 Geo-Map", padding=6)
right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

ttk.Label(left, text="🔍 IP or Domain").pack(anchor=tk.W)
entry = ttk.Entry(left, width=35)
entry.pack(pady=6)

output = scrolledtext.ScrolledText(left, wrap=tk.WORD, state='disabled', width=55, height=30)
output.pack(expand=True, fill=tk.BOTH)

map_canvas = tk.Label(right)
map_canvas.pack(expand=True)

def update_map_image(png_path):
    image = Image.open(png_path)
    image = image.resize((600, 450))
    img_tk = ImageTk.PhotoImage(image)
    map_canvas.config(image=img_tk)
    map_canvas.image = img_tk  # Keep reference

def run_lookup():
    entity = entry.get().strip()
    result = calculate_geo_risk_score(entity)
    output.config(state='normal')
    output.delete("1.0", tk.END)

    if "error" in result:
        output.insert(tk.END, f"❌ Error: {result['error']}")
        map_canvas.config(image='', text="Map unavailable")
    else:
        output.insert(tk.END, f"Entity: {result['entity']}\n\n📌 Location:\n")
        for k, v in result["location"].items():
            output.insert(tk.END, f"  {k}: {v}\n")
        output.insert(tk.END, "\n📊 Risk Metrics:\n")
        for k, v in result["risk_metrics"].items():
            output.insert(tk.END, f"  {k}: {v}\n")

        try:
            map_path = generate_static_map(result["location"])
            update_map_image(map_path)
        except Exception as e:
            output.insert(tk.END, f"\n⚠️ Map Error: {e}")
            map_canvas.config(image='', text="Map unavailable")

    output.config(state='disabled')

ttk.Button(left, text="Run Lookup", command=run_lookup).pack(pady=10)
root.mainloop()
