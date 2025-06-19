import json



# Define security
def label_service(severity_count):
    if severity_count["Critical"] > 0:
        return "At Risk"
    elif severity_count["High"] >= 1 or severity_count["Medium"] > 3:
        return "Caution"
    elif severity_count["Medium"] <= 2 and severity_count["Low"] <= 5:
        return "Secure"
    else:
        return "Needs Review"

# User Input

def get_vulnerability_data():
    severity_count = {}

    for severity in ["Critical", "High", "Medium", "Low"]:
        while True:
            try:
                count = int(input(f"Enter number of {severity} vulnerabilities: "))
                if count < 0:
                    print("Please enter a valid non-negative number.")
                    continue
                severity_count[severity] = count
                break
            except ValueError:
                print("Invalid input! Please enter a numeric value.")

    return severity_count

# Main Ex

if __name__ == "__main__":
    print("\n== Vulnerability Classification System ==")
    severity_count = get_vulnerability_data()
    security_label = label_service(severity_count)

    # OUTPUT

    report = {
        "Vulnerability Summary": severity_count,
        "Security Label": security_label
    }

    print("\n == Security Report ==")
    print(json.dumps(report, indent=4))
