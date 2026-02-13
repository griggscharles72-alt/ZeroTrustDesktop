#!/usr/bin/env bash
set -e

echo "=== Updating system ==="
sudo apt update && sudo apt upgrade -y

echo "=== Installing system dependencies ==="
sudo apt install -y \
    python3 python3-venv python3-dev python3-pip \
    build-essential curl git \
    libssl-dev libffi-dev

echo "=== Creating AI virtual environment ==="
python3 -m venv ~/ai_env

echo "=== Activating environment ==="
source ~/ai_env/bin/activate

echo "=== Upgrading pip tooling ==="
pip install --upgrade pip setuptools wheel

echo "=== Installing AI + Dev stack ==="
pip install \
    numpy scipy pandas matplotlib seaborn \
    scikit-learn \
    torch torchvision torchaudio \
    transformers datasets accelerate \
    fastapi uvicorn[standard] \
    requests httpx \
    black isort flake8 mypy pylint \
    jupyterlab ipython rich typer

echo "=== Verifying installation ==="
python - <<EOF
import torch, transformers, fastapi, numpy
print("Torch CUDA Available:", torch.cuda.is_available())
print("Core AI stack OK")
EOF

echo "=== Setup Complete ==="
echo "Activate anytime with:"
echo "source ~/ai_env/bin/activate"

