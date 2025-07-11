import stix2
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from rapidfuzz import fuzz
import webbrowser


# MITRE ATT&CK Enterprise STIX

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Def - MITRE data

def load_attack_data():
    try:
        response = requests.get(MITRE_URL)
        response.raise_for_status()
        return stix2.MemoryStore(stix_data=response.json()["objects"])
    except Exception as e:
        messagebox.showerror("Error", f"Could not fetch MITRE ATT&CK data:\n{e}")
        return None

# Original Search
def strict_search(data, keyword):
    keyword = keyword.lower()
    results = []
    for obj in data.query([stix2.Filter("type", "=", "attack-pattern")]):
        name = obj.get("name", "").lower()
        desc = obj.get("description", "").lower()
        if keyword in name or keyword in desc:
            results.append({
                "id": obj.external_references[0]["external_id"],
                "name": obj["name"],
                "description": desc.split("\n")[0],
                "url": obj.external_references[0].get("url", "")
            })
    return results

# Updated Fuzz Search
def fuzzy_search(data, keyword, threshold=60):
    results = []
    keyword = keyword.lower()
    for obj in data.query([stix2.Filter("type", "=", "attack-pattern")]):
        name = obj.get("name", "")
        desc = obj.get("description", "")
        combined = (name + " " + desc).lower()
        score = fuzz.token_set_ratio(keyword, combined)
        if score >= threshold:
            results.append({
                "id": obj.external_references[0]["external_id"],
                "name": name,
                "description": desc.split("\n")[0],
                "url": obj.external_references[0].get("url", ""),
                "score":score

            })
    return sorted(results, key=lambda x: x["score"], reverse=True)


# THEME AND VISUALS
BG = "#1e1e1e"
FG = "#e0e0e0"
HL = "#00c1ff"
FONT = ("Segoe UI", 10)

root = tk.Tk()
root.title("MITRE TTP Mapper")
root.geometry("800x500")
root.configure(bg=BG)

paned = tk.PanedWindow(root, orient="horizontal", sashrelief="raised", bg=BG)
paned.pack(fill="both", expand=True)

left = tk.Frame(paned, bg=BG)
paned.add(left, minsize=300)

right = tk.Frame(paned, bg=BG)
paned.add(right)



tk.Label(left, text="Search Behavior or Tool:", font=FONT, bg=BG, fg=FG).pack(padx=10, pady=(10, 0))
search_entry = tk.Entry(left, font=FONT, bg="#2a2a2a", fg=FG, insertbackground=FG)
search_entry.pack(fill="x", padx=10, pady=5)

use_fuzzy = tk.BooleanVar(value=True)
tk.Checkbutton(
    left,
    text="Enable Fuzzy Search",
    variable=use_fuzzy,
    bg=BG,
    fg=FG,
    selectcolor=BG,
    font=FONT,
    activeforeground=HL,
    anchor="w"
).pack(anchor="w", padx=10, pady=(0, 10))


result_list = tk.Listbox(left, font=FONT, bg="#2a2a2a", fg=FG, height=20)
result_list.pack(fill="both", expand=True, padx=10, pady=(5, 10))

tk.Label(right, text="Technique Details", font=("Segoe UI", 11, "bold"), bg=BG, fg=HL).pack(pady=10)
detail_text = tk.Text(right, wrap="word", bg="#252525", fg=FG, font=FONT, height=20)
detail_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

results = []
attack_data = load_attack_data()


# Bind search / Performing function / Search Handler
def perform_search(*_):
    global results
    keyword = search_entry.get().strip()
    if not keyword:
        return

    result_list.delete(0, "end")
    detail_text.delete("1.0", "end")

    if use_fuzzy.get():
        results = fuzzy_search(attack_data, keyword, threshold=60)
    else:
        results = strict_search(attack_data, keyword)

    if not results:
        result_list.insert("end", "No matches found.")
    else:
        for item in results:
            display_text = f"{item['id']} — {item['name']}"
            if "score" in item:
                display_text += f" ({item['score']}%)"
            result_list.insert("end", display_text)

# Detailed display - Clickable links, future improvement
def display_details(event):
    selection = result_list.curselection()
    if not selection or not results:
        return
    item = results[selection[0]]
    detail_text.delete("1.0", "end")
    detail_text.insert("end", f"TTP ID: {item['id']}\n")
    detail_text.insert("end", f"Name: {item['name']}\n\n")
    detail_text.insert("end", f"Description:\n{item['description']}\n\n")
    if item['url']:
        detail_text.insert("end", f"More Info: {item['url']}\n\n")
        detail_text.insert("end", f"(Ctrl+Click the link to open in browser)")

    def open_link(event):
        if item['url']:
            webbrowser.open(item['url'])

    detail_text.tag_config("link", foreground=HL, underline=True)
    start = detail_text.search(item['url'], "1.0", stopindex="end")
    if start:
        end = f"{start}+{len(item['url'])}c"
        detail_text.tag_add("link", start, end)
        detail_text.tag_bind("link", "<Control-Button-1>", open_link)

search_entry.bind("<Return>", perform_search)
result_list.bind("<<ListboxSelect>>", display_details)

# Execute
root.mainloop()
