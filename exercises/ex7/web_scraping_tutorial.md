# Web Scraping and Automation Ex. 7 
## A.Y. 2025/2026

### Contacts
* **Flavio Ciravegna:** [*flavio.ciravegna@polito.it*]
* **Silvia Sisinni:** [*silvia.sisinni@polito.it*]
* **Enrico Bravi:** [*enrico.bravi@polito.it*]
* **Lorenzo Ferro:** [*lorenzo.ferro@polito.it*]

---

## 0. Introduction to OSINT (Open Source Intelligence)

Let's start by introducing **OSINT**.

### What is OSINT?
Open Source Intelligence (OSINT) is the practice of collecting and analyzing information from publicly available sources to produce actionable intelligence. In cybersecurity, this is used for reconnaissance, threat hunting, and understanding an organization's attack surface.

### Common OSINT Techniques
*   **Search Engine Dorking (Google Dorking):** Using advanced search operators (e.g., `site:`, `filetype:`, `intitle:`) to find sensitive information indexed by search engines.
*   **WHOIS and DNS Lookups:** Investigating domain ownership, registration history, and server infrastructure.
*   **Social Media Intelligence (SOCMINT):** Analyzing public profiles to map organizational hierarchies or identify potential targets for social engineering.
*   **Metadata Analysis:** Extracting hidden data from public documents (PDFs, images) to reveal software versions, author names, or GPS locations.

### Web Scraping
Web scraping is the **automation layer** for OSINT. While a human can manually perform any of the tasks above, web scraping allows an analyst to:
1.  **Scale:** Monitor thousands of forums or news sites simultaneously.
2.  **Consistency:** Ensure data is collected in the exact same format every time.
3.  **Alerting:** Trigger immediate responses when specific keywords or threats appear online.

---

## 1. Overview: Motivations and Cybersecurity Applications

Web scraping is the automated process of extracting data from websites. While web browsers are built to render websites for human eyes, web scrapers are built to fetch, parse, and structure that underlying data for machine processing.

In the realm of cybersecurity and national defence, the ability to automate data collection from the web is a highly critical skill. It forms the backbone of several key security operations:

* **Open Source Intelligence (OSINT):** Security analysts and intelligence officers constantly scrape public forums, social media, news outlets, and even dark web marketplaces to gather actionable intelligence on threat actors, planned attacks, or leaked credentials.
* **Threat Intelligence Aggregation:** Scraping allows automated ingestion of Indicators of Compromise (IoCs) like malicious IP addresses, domain names, or file hashes from various security blogs and databases into a centralized defensive system.
* **Automated Auditing and Mapping:** Penetration testers scrape target websites to map out the application's attack surface, discovering hidden endpoints, employee emails (for social engineering), or outdated software versions exposed in the HTML source code.

---

## 2. Virtual Environments and Setup
Before installing external libraries for web scraping, it is best practice to create a Python virtual environment. 

### Windows
```cmd
python -m venv myenv
myenv\Scripts\activate
pip install beautifulsoup4 requests playwright pandas matplotlib seaborn
playwright install
```

### macOS / Linux
```bash
python3 -m venv myenv
source myenv/bin/activate
pip install beautifulsoup4 requests playwright pandas matplotlib seaborn
playwright install
```

---

## 3. Web Fundamentals: HTML, DOM, and CSS Selectors

To scrape a website, you must understand how it is structured.

### HTML (HyperText Markup Language)
HTML consists of **elements** (tags) like `<div>`, `<a>`, `<h1>`, and `<p>`.

### The DOM (Document Object Model)
The DOM represents the page as a tree of objects. Scrapers navigate this tree to find the "branches" containing the data.

### CSS Selectors
Scrapers use CSS selectors to locate specific elements:
- **Tag selector:** `p` 
- **ID selector:** `#header` 
- **Class selector:** `.price` 

---

## 4. What is a Scraper and Why Use It?

A **Web Scraper** is an automated script that simulates human browsing behavior.

1. **Efficiency:** Processes hundreds of pages in seconds.
2. **Real-time Monitoring:** Tracks changes in prices or security advisories.
3. **Data Aggregation:** Combines information from multiple sources.

---

## 5. Core Tools: BeautifulSoup vs. Playwright

The choice between tools depends on whether we need to analyze the "raw" code or the "rendered" result.

### BeautifulSoup (The Surgeon) - Static Analysis
*   **Purpose:** Parsing static HTML.
*   **The Advantage of Static Analysis:** By analyzing the raw HTML source code, you can inspect parts of the page that are **not rendered** in the browser. This includes:
    *   **Metadata and Hidden Tags:** `<meta>` tags, hidden input fields (`type="hidden"`), and internal configuration scripts.
    *   **Comments:** Developers often leave notes or commented-out code that might reveal sensitive info or "under-construction" features.
    *   **Speed:** It is extremely fast because it doesn't need to load images, CSS, or execute scripts.
*   **Example Usage:** Fetching the source code of a blog and searching for all `<h2>` tags containing "Cyberattack".

### Playwright (The Pilot) - Dynamic Execution
*   **Purpose:** Browser automation and dynamic content.
*   **The Necessity of Execution:** Modern "Single Page Applications" (SPAs) often start as an empty HTML shell. The actual content is generated by **JavaScript** while the page is running. To scrape these:
    *   **Running the Page:** You must launch a real browser engine (like Chromium) to execute the JS and see the final **behavior**.
    *   **Interactivity:** You can simulate human actions like clicking "Load More" buttons, scrolling to trigger lazy-loading, or filling out login forms.
*   **Example Usage:** Logging into a portal and waiting for a dashboard to load its charts via AJAX before extracting the values.

---

## 6. High-Level Data Gathering and Visualization

1. **Gathering:** Scraping thousands of entries.
2. **Cleaning:** Using **Pandas** to remove duplicates or format dates.
3. **Visualization:** Using **Matplotlib** to create charts.

---

## 7. The Scenario: Monitoring Threat Intelligence

**Background:** 
You are a Junior Security Analyst at an NCSC. You need to monitor "Threat Intelligence" blogs to keep track of malware campaigns.

**The Mission:**
Build an automated system that:
1. Scrapes a security blog for "Alert Titles", "Severity", and "Date".
2. Cleans the data.
3. Generates a visual report of alert severities.

---

## 8. Exercise: Scraping a Static Page (Narrative Example)

In this exercise, we will analyze the process of scraping **Quotes to Scrape** (`http://quotes.toscrape.com`).

### The Logic of the Scraper
Instead of manually copying quotes, your script should follow this logical flow:
1.  **Request:** The script sends an HTTP request to the server, identical to what a browser does when you type the URL.
2.  **Parse:** The returned HTML is a messy string of text. The script uses a parser (BeautifulSoup) to "understand" the structure.
3.  **Select:** You identify that every quote on the page is wrapped in a `div` with a specific class (e.g., `.quote`).
4.  **Extract:** For every one of these containers, the script looks specifically for the `span` containing the text and the `small` tag containing the author's name.
5.  **Store:** The script saves these pairs into a structured list, which can then be exported to a CSV file for further analysis.

---

## 9. Ethical and Legal Considerations

### 1. Technical Protocol: `robots.txt`
Check `example.com/robots.txt` to see which paths are "Disallowed".

### 2. Legal Frameworks
*   **Terms of Service (ToS):** Many sites forbid automated collection.
*   **Copyright and IP:** Expression of data is protected.
*   **Personal Data (GDPR):** Scraping emails or addresses requires a "lawful basis".
*   **CFAA:** Bypassing security measures to scrape data is a criminal offense.

---

## 10. Homework Exercises (Narrative Example)

**Objective: Market Analysis for Cyber Insurance**

Imagine you are working for a firm that provides cyber insurance. You need to understand the "value" of different items by scraping a mock e-commerce site like **Books to Scrape** (`http://books.toscrape.com`).

### Your Task Logic:
1.  **Multi-page Navigation:** The script must not only scrape the first page but also find the "Next" button link and follow it to subsequent pages.
2.  **Data Extraction:** For every book, the script should identify the title and the price. Note that the price usually contains a currency symbol (like `£`) which must be stripped away to treat the number as a mathematical value.
3.  **Analytical Processing:** Once the data is in a table, the script should calculate the average price of the entire catalog to establish a "baseline".
4.  **Visual Reporting:** The script should generate a distribution chart (histogram) to show if most items are "Budget" or "Premium", helping the insurance firm set their premiums.
