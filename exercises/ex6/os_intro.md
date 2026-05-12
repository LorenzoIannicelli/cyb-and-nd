# Cybersecurity and National Defence Ex. 6
## A.Y. 2025/2026

### Contacts
* **Flavio Ciravegna:** [*flavio.ciravegna@polito.it*]
* **Silvia Sisinni:** [*silvia.sisinni@polito.it*]
* **Enrico Bravi:** [*enrico.bravi@polito.it*]
* **Lorenzo Ferro:** [*lorenzo.ferro@polito.it*]

---

## Overview

The `os` module in Python provides a portable way of using operating system dependent functionality. It allows you to interface with the underlying operating system that Python is running on – be it Windows, macOS, or Linux. 

## Getting Started and Working Directory
Before doing anything with files, you often need to know **where** you are in the filesystem.

- **`os.getcwd()`**: Returns a string representing the current working directory.
- **`os.chdir(path)`**: Changes the current working directory to the specified `path`.

```python
import os
print("Current Directory:", os.getcwd())
# os.chdir('/tmp') # Example of changing directory
```

## Listing and Managing Directories
You can inspect the contents of a directory and create or remove them.

- **`os.listdir(path='.')`**: Returns a list containing the names of the entries in the directory given by `path`.
- **`os.mkdir(path)`**: Creates a single directory. Raises `FileExistsError` if it already exists.
- **`os.makedirs(name)`**: Recursive directory creation function. Like `mkdir()`, but makes all intermediate-level directories needed to contain the leaf directory.
- **`os.rmdir(path)`**: Removes (deletes) the directory `path`. The directory must be empty.

## File Operations
You can manipulate existing files directly.

- **`os.rename(src, dst)`**: Renames the file or directory `src` to `dst`.
- **`os.remove(path)`**: Removes (deletes) the file `path`. If `path` is a directory, an `OSError` is raised (use `os.rmdir()` for directories).

## Path Manipulation (`os.path`)
The `os.path` submodule contains useful functions on pathnames. It's often preferred to manually concatenating strings with `/` or `\` because `os.path` handles the differences between operating systems automatically.

- **`os.path.join(path, *paths)`**: Join one or more path components intelligently.
- **`os.path.exists(path)`**: Returns `True` if path refers to an existing path or an open file descriptor.
- **`os.path.isfile(path)`**: Returns `True` if path is an existing regular file.
- **`os.path.isdir(path)`**: Returns `True` if path is an existing directory.
- **`os.path.basename(path)`**: Returns the base name of pathname `path`.
- **`os.path.dirname(path)`**: Returns the directory name of pathname `path`.
- **`os.path.split(path)`**: Splits the pathname `path` into a pair, `(head, tail)` where `tail` is the last pathname component and `head` is everything leading up to that.

```python
full_path = os.path.join("folder", "subfolder", "file.txt")
print(full_path) # folder/subfolder/file.txt (on Unix/Linux)
```

## Walking a Directory Tree
When you need to process all files in a directory and all of its subdirectories, `os.walk()` is incredibly powerful.

- **`os.walk(top)`**: Generates the file names in a directory tree by walking the tree either top-down or bottom-up. For each directory in the tree rooted at directory `top`, it yields a 3-tuple: `(dirpath, dirnames, filenames)`.

```python
for dirpath, dirnames, filenames in os.walk('.'):
    print(f"Found directory: {dirpath}")
    for file_name in filenames:
        print(f"  File: {file_name}")
```

## Environment Variables
You can access environment variables of the operating system.

- **`os.environ`**: A dictionary-like object mapping string environment variable names to their string values.
- **`os.getenv(key, default=None)`**: Return the value of the environment variable `key` if it exists, or `default` if it doesn't.

```python
# Getting the USER environment variable
user = os.getenv('USER', 'Unknown')
print(f"Current user is: {user}")
```

## Processes

The `os` module provides functions to manage and interact with system processes — a fundamental concept in operating systems and in security (e.g., monitoring running services, sending signals, detecting rogue processes).

### Process IDs

- **`os.getpid()`**: Returns the current process ID.
- **`os.getppid()`**: Returns the parent process's ID.

```python
print(f"My PID: {os.getpid()}")
print(f"Parent PID: {os.getppid()}")
```

### Sending Signals

- **`os.kill(pid, sig)`**: Sends a signal `sig` to the process with ID `pid`. Common signals include `signal.SIGTERM` (graceful termination) and `signal.SIGKILL` (forced kill).

```python
import signal

# Example: send SIGTERM to a process (use with caution!)
# os.kill(some_pid, signal.SIGTERM)
```

### Running System Commands

- **`os.system(command)`**: Executes the command (a string) in a subshell. Returns the exit status.

**⚠️ Warning**: never pass unsanitized user input to `os.system()`, this is a classic **command injection** vulnerability.

```python
os.system('echo "Hello from the shell"')
```

### The `subprocess` Module (Recommended Alternative)

The `subprocess` module is the modern, safer, and more flexible replacement for `os.system()`.

- **`subprocess.run(args, ...)`**: Runs a command described by `args`. Returns a `CompletedProcess` instance.

```python
import subprocess

result = subprocess.run(['ls', '-la'], capture_output=True, text=True)
print(result.stdout)
```

> **Why `subprocess` over `os.system`?** With `subprocess.run(["cmd", "arg"])`, the arguments are passed as a list, avoiding shell interpretation and thus **preventing command injection**. With `os.system("cmd " + user_input)`, an attacker could inject `; rm -rf /` via `user_input`.

## Security Aspects: Permissions and Access
In the context of cybersecurity, file permissions are critical. Improper permissions can lead to privilege escalation or unauthorized data access. The `os` module allows you to inspect and modify these permissions.

- **`os.chmod(path, mode)`**: Changes the mode (permissions) of `path` to the numeric `mode` (usually specified in octal, e.g., `0o644`). 
- **`os.stat(path)`**: Performs a `stat()` system call on the given path. The return value is an object whose attributes correspond to the members of the stat structure, namely `st_mode` (protection bits).
- **`os.getuid()`** / **`os.geteuid()`**: Returns the current (real/effective) user ID. Useful to check if a script is running as root.

You can use the `stat` module in conjunction with `os.stat` to interpret the mode.

```python
import os
import stat

# Create a file and set restrictive permissions (read/write for owner only: rw-------)
open('secret.txt', 'w').close()
os.chmod('secret.txt', 0o600)

# Check permissions
file_stat = os.stat('secret.txt')
print(f"File mode (octal): {oct(file_stat.st_mode)}")

# Check if running as root
if os.geteuid() == 0:
    print("WARNING: Running as root!")
```

Another critical security consideration is **Environment Variables**. Sensitive information like API keys, database passwords, or secret tokens are often injected via environment variables. Exposing them or logging `os.environ` can be a significant security vulnerability. 

---
**Next Steps**: Proceed to the `os_exercises.ipynb` notebook to practice these concepts!
