
JPIR project is fork of Stanford library pir-0.1

Private Information Retrieval Library 0.1
https://crypto.stanford.edu/pir-library/

It has implementation for Computational Private Information Retrieval Protocols (CPIR)

PIR-0.1 is refactored, rewritten as JPIR by Sashank Dara (sashank.dara@gmail.com)

It is written for research purposes and not for production use.

TEST classes has its usage in standalone mode.

REST based Client/Server communication is supported for private queries

Usage :


Download or git clone the project
change directory to jpir
Run the below command on your terminal
mvn clean install

This would generate target/jpir-1.0-SNAPSHOT-jar-with-dependencies.jar

Server Setup :

Copy the jar file to some server
Copy the server.properties to the server

Modify the server.properties with appropriate input file (for database of words)

Run the below command to start the server

java -jar jpir-1.0-SNAPSHOT-jar-with-dependencies.jar


Client Setup :

Update the client.properties with Server's IP Address
From your IDE just run the PIR_RestClient.java

The output would be printed on the console.