
#!/bin/bash
# Cleans temporary runtime data for both clients

echo "Cleaning runtime data..."

rm -rf python_client/data/*
rm -rf python_client/tmp/*
rm -rf java_client/tmp/*

echo "Done."
