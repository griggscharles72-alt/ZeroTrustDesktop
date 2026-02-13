# AI Development Environment Bootstrap

This repository contains a single Bash script designed to reproducibly set up a full Python-based AI and development environment on Ubuntu systems.

The goal is to eliminate manual setup, avoid breaking system Python, and provide a clean, portable workflow suitable for local development, experimentation, and collaboration.

---

## What This Script Does

The `bootstrap_ai_stack.sh` script performs the following actions:

1. Updates the system package index and upgrades installed packages
2. Installs core system dependencies required for Python development
3. Creates an isolated Python virtual environment
4. Installs a complete AI and development toolchain inside the virtual environment
5. Verifies that core libraries are working correctly

All Python packages are installed **inside a virtual environment**, not system-wide.

---

## Included Tooling

### Core Python Stack
- Python 3
- pip, setuptools, wheel
- Virtual environment support

### Scientific & Data Libraries
- NumPy
- SciPy
- Pandas
- Matplotlib
- Seaborn

### Machine Learning & AI
- PyTorch
- TorchVision
- TorchAudio
- Hugging Face Transformers
- Datasets
- Accelerate

### API & Services
- FastAPI
- Uvicorn
- Requests
- HTTPX

### Developer Tools
- IPython
- JupyterLab
- Black
- Isort
- Flake8
- Mypy
- Pylint
- Rich
- Typer

---

## Requirements

- Ubuntu 24.04 or later (or compatible Debian-based distribution)
- sudo privileges
- Internet connection

No GPU is required. If a CUDA-capable GPU is present, PyTorch will automatically detect it.

---

## Usage

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd <repo-directory>

