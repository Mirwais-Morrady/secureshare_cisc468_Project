
#!/bin/bash
# Starts the Python secure share client

cd python_client || exit

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python -m venv .venv
fi

source .venv/bin/activate

pip install -r requirements.txt

echo "Starting Python client..."
python run_client.py
