
#!/bin/bash
# Builds and runs the Java secure share client

cd java_client || exit

echo "Building Java client..."
mvn -q compile

echo "Running Java client..."
mvn exec:java -Dexec.mainClass="com.cisc468share.Main"
