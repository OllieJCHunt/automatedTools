import tkinter as tk
import csv
from datetime import datetime
import os
import subprocess

from tkinter import messagebox

# Initialize window
root = tk.Tk()
root.title("Vulnerability Label Classifier")
root.geometry("360x330")
root.resizable(False, False)

# Labels
tk.Label(root, text="Service Title:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
tk.Label(root, text="Critical Count:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
tk.Label(root, text="High Count:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
tk.Label(root, text="Medium Count:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
tk.Label(root, text="Low Count:").grid(row=4, column=0, padx=10, pady=5, sticky="e")

# Entry fields
entry_service = tk.Entry(root)
entry_critical = tk.Entry(root)
entry_high = tk.Entry(root)
entry_medium = tk.Entry(root)
entry_low = tk.Entry(root)

entry_service.grid(row=0, column=1, padx=10, pady=10)
entry_critical.grid(row=1, column=1, padx=10, pady=5)
entry_high.grid(row=2, column=1, padx=10, pady=5)
entry_medium.grid(row=3, column=1, padx=10, pady=5)
entry_low.grid(row=4, column=1, padx=10, pady=5)

# Result & File Display
result_label = tk.Label(root, text="", font=("Helvetica", 11, "bold"), justify="center")
result_label.grid(row=6, column=0, columnspan=2, pady=10)

file_location_label = tk.Label(root, text="", font=("Helvetica", 9), fg="grey", wraplength=360, justify="center")
file_location_label.grid(row=6, column=0, columnspan=2, pady=(2, 5))

# Severity Function
def classify_by_severity():
    try:
        service = entry_service.get().strip()
        critical = int(entry_critical.get())
        high = int(entry_high.get())
        medium = int(entry_medium.get())
        low = int(entry_low.get())

        score = (critical * 5) + (high * 3) + (medium * 2) + (low * 1)

        if critical > 0 or score >= 25:
            label = "Critical"
        elif high >= 3 or score >= 15:
            label = "High"
        elif medium >= 2 or score >= 7:
            label = "Moderate"
        else:
            label = "Low"

        service_display = service if service else "Unnamed Service"
        result_label.config(text=f"Service: {service_display}\nLabel: {label}", fg="black")

        # Save data to CSV
        with open("vulnerability_tracking.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                service_display,
                critical,
                high,
                medium,
                low,
                label
            ])

        filepath = os.path.abspath("vulnerability_tracking.csv")
        file_location_label.config(text=f"Saved to: {filepath}")

        # Summary
        summary = f"Service: {service_display}\n\n" \
                  f"Critical: {critical}\n" \
                  f"High: {high}\n" \
                  f"Medium: {medium}\n" \
                  f"Low: {low}\n\n" \
                  f"Assigned Label: {label}"
        messagebox.showinfo("Summary", summary)

    except ValueError:
        result_label.config(text="Please enter valid integers.", fg="red")

# Open Function

def open_csv_file():
    filepath = os.path.abspath("vulnerability_tracking.csv")
    try:
        os.startfile(filepath) #Windows
    except AttributeError:
        subprocess.call(["open", filepath]) # MAC Fallback

    except Exception as e:
        messagebox.showerror("Error", f"Couldn't open file:\n{e}")


# Button
tk.Button(root, text="Generate Label", command=classify_by_severity).grid(row=5, column=0, columnspan=2, pady=15)
tk.Button(root, text="View File", command=open_csv_file).grid(row=8, column=0, columnspan=2, pady=15)

root.mainloop()
