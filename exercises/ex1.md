# Cybersecurity and National Defense
## A.Y. 2025/2026

### Contacts
* **Flavio Ciravegna:** [*flavio.ciravegna@polito.it*]
* **Silvia Sisinni:** [*silvia.sisinni@polito.it*]
* **Enrico Bravi:** [*enrico.bravi@polito.it*]
* **Lorenzo Ferro:** [*lorenzo.ferro@polito.it*]

---

# Agenda
1. **Material research:** Finding and organizing sources.
2. **LaTeX:** Writing professional academic documents.
3. **Git & Version control:** Tracking your work.
4. **Effective presentations:** Sharing your research results properly.

---
---

# Part 1: Material research

## Structuring a Research Project
Generally, a research project is structured following the IMRAD format. The acronym IMRAD stands for:

* **I**ntroduction: Why did you do the work?
* **M**ethods: How did you do it?
* **R**esults: What did you find?
* **a**nd
* **D**iscussion: What does it mean?

## Where to find quality sources
One of the most important part of the research is to find quality sources.

* **Good sources:**
    * IEEE Xplore (https://ieeexplore.ieee.org/)
    * ACM Digital Library (https://dl.acm.org/)
    * Google Scholar (https://scholar.google.com/)
    * ScienceDirect (https://www.sciencedirect.com/)
    * University Library Databases
    * **Tip:** Use Boolean operators (`AND`, `OR`, `NOT`) to narrow searches.
* **Bad:** Wikipedia, blogs, unofficial websites, etc.

---
---

# Module 2: LaTeX for academic writing

## What is LaTeX?
* **Document markup language**
    * not an editor like Microsoft Word
    * you write code, compile it, and get a formatted PDF
* **Easiest way to start:**
    * Overleaf (cloud-based, no installation required)
        * https://www.overleaf.com/

## Why use LaTeX?
**Pros:**
* **Separate the content from the formatting**
    * formatting is done automatically
    * figures, tables, and text are placed properly
    * easier to update the content *without breaking the formatting*
    * focus on writing, not adjusting the document format
* Handles mathematical formulas
* **Auto-updates numbering** (figures, tables, sections)
* Standard tool in computer science and engineering

**Cons:**
* Steep learning curve at the beginning
    * not as intuitive as *"What You See Is What You Get"* editors (i.e., Word) 


## The basic structure of a LaTeX file
```latex
\documentclass{article}

% Preamble (Packages go here)
\usepackage{amsmath}
% other packages here

\begin{document}
% Content goes here
\title{LaTeX Document}
\maketitle

\section{Introduction}
Hello, World!
\end{document}
```


## Bibliography

* **BibTeX / BibLaTeX:** Tools to manage references in LaTeX.
    * Keeps citation data separated from the main document formatting.
* **The `.bib` File:** A plain text database of your references.
    * Each entry is structured with fields (author, title, year, ...).
* **The Workflow:**
    1. Add the references to a single `.bib` file.
    2. Include the *cite* package
        * insert `\usepackage{cite}` in the preamble of your `.tex` file
    3. Cite the references in your main `.tex` document (e.g., `\cite{citation_key}`).
    4. Compile to automatically extract and generate an ordered reference list.
* **Advantages:**
    * Consistent formatting across styles (APA, IEEE, Chicago, etc.).
    * Reusable across multiple papers and different projects.

### Templates of bibtex entries

#### Tips
* Author names: {LastName1, FirstName1 and LastName2, FirstName2 and ...}
    * Example: {Doe, John and Smith, Jane and ...}
* Insert the Digital Object Identifier (DOI) whenever possible
    * If you don't find it, insert the url in a note field

#### Conference proceedings
```bibtex
@inproceedings{citekey,
    author    = {Authors Names},
    title     = {{Title of the Paper}},
    booktitle = {Title of the Conference Proceedings},
    month     = {Month},
    year      = {Year},
    address   = {City (State, Country)},
    pages     = {AAA--AAA},
    doi       = {DOI},
}
```
Usage example:
```bibtex
@inproceedings{keylime,
    author                  = {Schear, Nabil and Cable, Patrick T and Moyer, Thomas M and Richard, Bryan and Rudd, Robert},
    title                   = {{Bootstrapping and Maintaining Trust in the Cloud}},
    booktitle               = {32nd Annual Conference on Computer Security Applications},
    month                   = dec # " 5-8,",
    year                    = 2016,
    address                 = {Los Angeles (CA, USA)},
    pages                   = {65--77},
    doi                     = {10.1145/2991079.2991104}
}
```

#### Journal article
```bibtex
@article{citekey,
    author    = {Authors Names},
    title     = {{Title of the Paper}},
    journal   = {Journal Name},
    volume    = {Volume},
    number    = {Number},
    month     = {Month},
    year      = {Year},
    pages     = {1--23},
    doi       = {10.1016/j.cose.2024.104254}
}
```

Usage example:
```bibtex
@article{CFA_survey,
    author                 = {Sha, Zhanyu and Shepherd, Carlton and Rafi, Amir and Markantonakis, Konstantinos},
    title                  = {{Control-flow attestation: Concepts, solutions, and open challenges}},
    journal                = {Computers \& Security},
    year                   = 2025,
    month                  = mar,
    pages                  = {1--23},
    doi                    = {10.1016/j.cose.2024.104254}
}
```
---

#### Collection of book chapters
```bibtex
@incollection{citekey,
    author                = {Authors Names},
    title                 = {{Title}},
    booktitle             = {{Book Title}},
    editor                = {Editors Names},
    publisher             = {Publisher},
    year                  = {Year},
    pages                 = {AAA-AAA},
    isbn                  = {000-0-000-00000-0},
    doi                   = {DOI}
}
```

Usage example:
```bibtex
@incollection{tc,
    author                = {Lioy, Antonio and Ramunno, Gianluca},
    title                 = {{Trusted Computing}},
    booktitle             = {{Handbook of Information and Communication Security}},
    editor                = {Stavroulakis, Peter and Stamp, Mark},
    publisher             = {Springer},
    year                  = 2010,
    pages                 = {697-717},
    isbn                  = {978-3-642-04117-4},
    doi                   = {10.1007/978-3-642-04117-4_32}
}
```
---

### Book
```bibtex
@book{citekey,
    author                = {Authors Names},
    title                 = {{Title}},
    publisher             = {Publisher},
    year                  = {Year},
    isbn                  = {000-0-000-00000-0}
}
```

Usage example:
```bibtex
@book{seceng,
    author                = {Anderson, Ross J.},
    title                 = {{Security engineering}},
    publisher             = {Wiley},
    year                  = {2008},
    _isbn                 = {978-0-470-06852-6}
}
```

### Webpage (or other resources)
```bibtex
@misc{citekey,
    author                = {Author},
    title                 = {{Title}}
    note                  = {\url{<website_url>}}
}
```

Usage example:
```bibtex
@misc{tpm_spec,
    author                  = {{Trusted Computing Group}},
    title                   = {{TPM 2.0 Specifications (Architecture)}},
    note                    = {\url{https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf}}
}
```


### RFC
```bibtex
@misc{citekey, crossref={rfc0000}}
@misc{rfc0000,
    author                  = {Authors Names},
    title                   = {{Remote ATtestation procedureS (RATS) Architecture}},
    howpublished            = {\rfc{0000}},
    year                    = {Year},
    month                   = {Month},
    doi                     = {DOI},
}
```
Usage example:
```bibtex
@misc{rats, crossref={rfc9334}}
@misc{rfc9334,
    author                  = {Birkholz, Henk and Thaler, Dave and Richardson, Michael and Smith, Ned and Pan, Wei},
    title                   = {{Remote ATtestation procedureS (RATS) Architecture}},
    howpublished            = {\rfc{9334}},
    year                    = 2023,
    month                   = jan,
    doi                     = {10.17487/RFC9334},
}
```
NOTE: to use this entry, insert the following in the latex source file
```latex
\newcommand{\rfc}[1]{RFC-#1\xspace}
```

---
---

# Part 3: Git & Version control
Have you ever had a folder looking like this?
```bash 
your_folder
├── report_draft.pdf
├── report.pdf
├── report_final.pdf
├── report_final_really.pdf
└── report_final_USE_THIS_ONE.pdf
```

Git solves this problem.

## What is Git?
* **Version control system**
    * tracks changes in files over time
    * allows you to revert to previous versions
    * facilitates collaboration
* **Distributed**
    * each developer has a full copy of the repository
    * no single point of failure
    * works offline

## Main Git components
* **Working directory:** The local directory where **you actually read, write, and edit** your project files.
* **Staging area:** A space where you gather and **prepare modified files** that are going to be in your **next commit**.
* **Local Repository:** The **database on your own machine** where Git stores the committed history of changes.
* **Remote Repository:** A central version of **your repository hosted on a server** (e.g., GitHub, GitLab) used for backup, sharing, and collaborating.

## The basic Git workflow:
1. **Initialize** a repository
2. **Stage** changes
3. **Commit** changes
4. **Push** changes to a remote repository

```text
Working Directory        Staging Area          Local Repo             Remote Repo
        |                      |                    |                      |
        |------ git add ------>|                    |                      |
        |<------ git rm -------|                    |                      |
        |                      |--- git commit ---->|                      |
        |                      |                    |--- git push -------->|
        |                      |                    |                      |
        |<--- git checkout ----|                    |<----- git fetch -----|
        |<------------------------- git merge -----------------------------|
        |<------------------------- git pull ------------------------------|
```
## Git from VS Code

### Step 1: Download VS Code
Download from https://code.visualstudio.com/

### Step 2: Download and install Git
* Download from https://git-scm.com/
* Install Git

### Step 3: Configure Git
Run the following commands in the terminal:
```bash
git config --global user.name "Your Name"
git config --global user.email "[EMAIL_ADDRESS]"
``` 
This will configure Git to use your name and email for all your repositories.

### Step 4: Initialize a repository
You have different options:
* Initialize a new repository: Create a new Git repository for your current folder.
* Clone a repository: Clone an existing repository from GitHub or another Git host.

#### Initialize a new repository
* Click on the **Source Control** icon in the left sidebar (it looks like three connected dots)
* click on the **Initialize Repository** button
* select the folder where you want to initialize a repository
* click on the **Create Repository** button

#### Clone a repository
* Click on the **Source Control** icon in the left sidebar
* click on the **Clone Repository** button
* on the top of the screen, under the bar, it will appear a tab asking for the *repository URL*
    * insert the URL of the repository
    * or click on **Clone from GitHub**
        * then, select the proper repository
* select the folder where you want to clone the repository
* click on the **Select as Repository Destination** button


### Step 5: Stage changes
Once you have made changes to your files, you need to stage them before committing.

To do this:
* Click on the **Source Control** icon in the left sidebar
* you will see a list of files that have been modified under the **Changes** section
    * click on the **+** icon next to the file name to stage it
        * or click on the **+** icon next to the **Changes** section to stage all files
    * you can also discard changes by clicking on the proper icon next to the file name

### Step 6: Commit changes
This will save the changes from the staging area to the local repository.

To do this:
* Click on the **Source Control** icon in the left sidebar
* enter a commit message in the text box at the top
* click on the **Commit** button

### Step 7: Push changes
After the commit(s) are done, you can push the changes to the remote repository.

To do this:
* Click on the **Source Control** icon in the left sidebar
* click on the **Push** button

## Git from command line
### Initialize a repository
```bash
git init
```

### Stage changes
```bash
git add .
```

### Commit changes
```bash
git commit -m "My first commit"
```

### Push changes
```bash
git push origin main
```

### Basic Git commands
* `git add <file>` - Stage a specific file (use `git add .` for all changes)
* `git rm <file>` - Remove a file from the working directory and staging area
* `git commit -m "<message>"` - Commit your staged changes with a descriptive message specified in the double quotes
* `git status` - Show the status of the repository
* `git log` - Show the commit history
* `git checkout <branch_name>` - Switch to a specific branch
* `git checkout <commit_hash>` - Checkout a previous commit
* `git clone <repository_url>` - Clone a repository
* `git pull` - Pull changes from a remote repository
* `git push` - Push changes to a remote repository

### Advanced Git commands
* `git branch` - Show the branches
* `git merge` - Merge branches
* `git diff` - Show the differences between commits
* `git reset` - Reset the repository to a previous commit

### References
* Official Git documentation
    * https://git-scm.com/doc
* Learn Git step-by-step
    * https://learngitbranching.js.org/
* Course Github repository
    * https://github.com/torsec/cyb-and-nd
    
---
---

# Part 4: Presentations
Reccomendations for an effective and clear presentation.

## Guidelines for PowerPoint formatting
* Each slide must be visualised for **at most 1-2 minutes**
* Format the slides to facilitate **readability**
    * **never** go below 18 pt as font size
    * recommended **24 pt for normal text, 30 pt for titles**
    * use *sans serif* fonts
        * Arial, Verdana, Helvetica, etc.
        * they are easier to read
    * **high-contrast colors**
        * blue, black, dark green fonts on a white background
        * white, yellow, red, light green on darker backgrounds
* **Avoid wall of text**
    * presentations are not book paragraphs
    * omit non-essential words
* use capital letters properly
    * proper names, acronyms, etc.
    * **don't** use capital letters for
        * first word of a paragraph in a list
        * words *after* the first one in a title

* **Recommended:** format A4
    * other generic formats (e.g., 4:3 or 16:9) depends on the projector settings

## Example of 15 minutes presentation
* A title slide
* 2 or 3 slides to introduce the problem/topic
* some slides to explain your activity
* some slides to explain the results
* a conclusion slide