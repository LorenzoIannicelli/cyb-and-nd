import requests
import json
import pandas as pd
import matplotlib.pyplot as plt

example = "Apple"
case_study = "Viasat KA-SAT"

base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "keywordSearch": example,
    "resultsPerPage": 200,
    "startIndex": 0,
    "pubStartDate": "2018-01-01T00:00:00.000Z",
    "pubEndDate": "2018-04-30T00:00:00.000Z"
}

print("Querying the NVD API (this may take a few seconds)...")
response = requests.get(base_url, params=params)

if response.status_code == 200:
    data = response.json()
    with open("cve_data.json", "w") as f:
        json.dump(data, f, indent=4)

    total_results = data.get("totalResults", 0)
    print(
        f"Success! Saved data. The NVD database returned {total_results} total matching CVEs, and we downloaded {len(data.get('vulnerabilities', []))}.")
else:
    print(f"Error {response.status_code}: Failed to retrieve data.\n{response.text}")

with open("cve_data.json", "r") as f:
    raw_data = json.load(f)

vulnerabilities = raw_data.get("vulnerabilities", [])

parsed_cves = []
for item in vulnerabilities:
    cve_details = item.get("cve", {})

    cve_id = cve_details.get("id", "Unknown")
    cve_published = cve_details.get("published", None)
    dt = pd.to_datetime(cve_published, format="%Y-%m-%dT%H:%M:%S.%f", errors='coerce')

    parsed_cves.append({
        'id': cve_id,
        'published': dt,
        'day_of_week': dt.day_name()
    })

df = pd.DataFrame(parsed_cves)
#print(df)

day_counts = df.groupby('day_of_week', observed=False).size().reset_index(name='count')
#print(day_counts)

ordered_day_cnt = day_counts.sort_values(by=['count'], ascending=False)
print(ordered_day_cnt)

plt.figure(figsize=(10, 6))
plt.bar(ordered_day_cnt["day_of_week"], ordered_day_cnt["count"], color="steelblue", edgecolor="black")

plt.title(f"Vulnerabilities by Day of the Week - {example}", fontsize=16)
plt.xlabel("Day of the Week", fontsize=12)
plt.ylabel("Number of Vulnerabilities", fontsize=12)

plt.xticks(rotation=45, ha="right")  # tilt labels to avoid overlap
plt.tight_layout()                   # adjust layout to prevent clipping
plt.savefig("cve_by_day.png", dpi=150)
plt.show()