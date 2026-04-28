# Cybersecurity and National Defence Ex. 3
## A.Y. 2025/2026

### Contacts
* **Flavio Ciravegna:** [*flavio.ciravegna@polito.it*]
* **Silvia Sisinni:** [*silvia.sisinni@polito.it*]
* **Enrico Bravi:** [*enrico.bravi@polito.it*]
* **Lorenzo Ferro:** [*lorenzo.ferro@polito.it*]

---

## Overview 

This laboratory focuses on automating interactions with external RESTful JSON services, specifically the National Vulnerability Database (NVD) API, to collect cybersecurity metrics. We subsequently introduce automated data analysis and visualization using the Python ecosystem.

### Prerequisites & Virtual Environments
Before delving into the code inside the **Jupyter Notebook (`nvd_api_tutorial.ipynb`)**, ensure you have created a Python virtual environment to isolate the project dependencies.

```bash
# Mac/Linux Environments
python3 -m venv myenv # skip if arleady created 
source myenv/bin/activate
pip install requests pandas matplotlib jupyter nbformat

# Windows Environments
python -m venv myenv # skip if arleady created 
myenv\Scripts\activate
pip install requests pandas matplotlib jupyter nbformat
```

---

## 1. The NVD Vulnerability API

### Theoretical Background
The NVD API serves as the single source of truth for documented vulnerabilities worldwide, identified by Common Vulnerabilities and Exposures (CVE) IDs. The RESTful architecture allows remote computers to reliably fetch dynamic feeds containing vulnerability characteristics, hardware applicability, software patches, and impact metrics.

### Key API Parameters
- **`cpeName`**: Allows querying for vulnerabilities attached to a specific Common Platform Enumeration (CPE) string (e.g., specific versions of Microsoft Windows or the Linux Kernel).
- **`keywordSearch`**: Returns any CVE where the chosen terms exist somewhere in the description.
- **`cvssV3Severity`**: Filters specific risk categories such as `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **`startIndex` & `resultsPerPage`**: Because the NVD tracks over 300,000 active CVEs, requests must use **offset-based pagination**. The application asks the API for a slice of results (e.g., 0 to 100), processes them, and then increments the `startIndex` parameter for the next batch until the data stream exhausts.

### Data Format: JSON Details
The API returns a JSON (JavaScript Object Notation) payload. A common nested structure outlines `totalResults` at the root array, along with a deeply nested `vulnerabilities` list holding individual `cve` dictionaries. The metrics describing the impact severity (e.g., standard CVSS scores) require navigating down `metrics.cvssMetricV31[0].cvssData.baseScore` to access accurately.

---

## 2. Advanced Data Analysis: Pandas

### Theoretical Background
When managing JSON structures mapped to tens of thousands of incidents, standard lists and dictionary implementations in Python become extremely cumbersome and memory-intensive to manage manually.

`pandas` acts as an incredibly performant relational bridge. It loads data structures into highly optimized objects known as **DataFrames** (conceptually identical to an SQL Table or a Microsoft Excel sheet).

### Core Operations
1. **Flattening / Normalization**: We typically extract the exact key-value pairs needed from nested hierarchies, compiling a flat list of simple dictionaries.
2. **DataFrame Loading**: We push this flat list into `pd.DataFrame()`.
3. **Type Manipulation**: Raw JSON returns dates as ISO 8601 strings. Using Pandas, we apply vectorized conversions (`pd.to_datetime()`) that automatically format those string components into queryable datetime indices, unlocking timeseries logic (e.g., selecting all CVEs tracked in July 2024).
4. **Time-Series Aggregation**: Once dates are properly formatted, we can turn them into a temporal index with `.set_index()`. Using the `.resample('ME')` (Month-End) operation, we group records by equal time intervals and compute operations like the `mean()` severity of vulnerabilities over that specific month.

---

## 3. Threat Visualization: Matplotlib

### Theoretical Background
Cognitive interpretation of pure text drops drastically as datasets grow. `matplotlib` handles drawing vector graphics and plotting statistical metrics over coordinate planes.

By integrating `pandas` datasets with `matplotlib` logic, you can easily represent:
- **Line Charts**: Graphing continuous quantitative data over time, making it the premier choice for mapping the trajectory of average severity scores month by month.
- **Bar Charts**: Showcasing CVSS severity level frequency.
- **Histograms / Timelines**: Identifying seasonal spikes in disclosed vulnerabilities against a specific software suite.
- **Pie Charts**: Segmenting compromised domains or system architectural classes (Network, Local, Adjacent).

---

## 4. Main Implementations & Methodological Choices

**1. Data Retrieval**
- `requests.get()`: We prefer this over manual socket creation or scraping because the NVD explicitly exposes a RESTful JSON endpoint. The `requests` library seamlessly negotiates the HTTPS handshake, manages query parameter appending (`params=`), and directly converts raw bytecode into a structured Python dictionary (`response.json()`).

**2. Data Structuring & Analysis**
- `pandas.DataFrame()`: While native Python lists and dictionaries handle API data well initially, manually looping over tens of thousands of incidents is extremely sluggish. We chose DataFrames to migrate the nested JSON into a high-performance relational table that supports bulk processing.
- `pd.to_datetime()`: This method is vital. Raw API timestamps are transmitted as ISO 8601 text (`"2024-01-01T..."`). Processing them into queryable `datetime` sequence objects automatically resolves complex calendar arithmetic.
- `.set_index()` and `.resample('ME')`: We avoid writing complex Python loops for timeline extraction. Setting the chronological timestamp column as the DataFrame Index allows `.resample('ME')` (Month-End) to algorithmically compartmentalize all records mapping to a specific month, extracting an aggregated metric (like `.mean()` severity) sequentially.

**3. Visualization Strategies**
- `DataFrame.plot()`: Although we imported `matplotlib.pyplot`, we almost exclusively used Pandas' automated wrapper methods (`df.plot(kind='line')`). We chose this path because Pandas integrates natively with its own indices, automatically handling X-axis timestamp scaling, legend labeling, and dataset sorting without requiring dozens of lines of pure Matplotlib boilerplate drawing coordinates.

---

## 5. Homework Exercises

**Exercise: Vulnerabilities by Day of the Week**
Fetch the last 200 vulnerabilities related a topic of your interest. Convert the published dates to Pandas datetime objects. Extract the day of the week (e.g., Monday, Tuesday) for each vulnerability. Group the data to count the number of vulnerabilities detected on each day of the week. Find and print the day with the most vulnerabilities detected. Finally, print the total counts for each day in descending order (e.g., "Monday: 30, Wednesday: 10, etc.") and use Matplotlib to plot a bar chart showing these frequencies, ensuring the axes are properly labeled and a title is included.
