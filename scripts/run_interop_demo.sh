
#!/bin/bash
# Launches both Python and Java clients for a quick interoperability demo

echo "Starting Python client in background..."
bash run_python_client.sh &

PY_PID=$!

sleep 3

echo "Starting Java client..."
bash run_java_client.sh

kill $PY_PID
