
**JPIR Private Information Retrieval in Java**

----------

JPIR project is fork of Stanford library [pir-0.1](https://crypto.stanford.edu/pir-library/). It is refactored, rewritten as JPIR by Sashank Dara (sashank.dara (_at_) gmail.com)

[Private Information Retrieval](https://en.wikipedia.org/wiki/Private_information_retrieval) is a protocol that allows a user to retrieve an item from a server in possession of a database without revealing which item is retrieved

JPIR has implementation for Computational Private Information Retrieval Protocols (CPIR). It is written for research purposes and not for production use.

REST based Client/Server communication is supported for private queries

**Usage :**

Download or git clone the project
change directory to jpir
Run the below command on your terminal to generate PIRServer.jar

    mvn clean install
    mv target/jpir-1.0-SNAPSHOT-jar-with-dependencies.jar PIRServer.jar

**Server Setup :**

 1. Copy the `PIRServer.jar` file to some server.
 2. Copy the `server.properties` to the server
 3. Modify the server.properties with appropriate input file (as database)
 4. Run the below command to start the server
	  `java -jar PIRServer.jar`

**Client Setup :**

 5. Update the `client.properties` with Server's IP Address 
 6. From your IDE just run the *PIR_RestClient.java*
 7. For running it from command line
	 8.  Change the `main` file in `pom.xml` with `PIR_RestClient`
	 9.   `maven clean install`
	 10. `mv target/jpir-1.0-SNAPSHOT-jar-with-dependencies.jar PIRClient.jar`
	 11. `java -jar PIRClient.jar`   (Will execute the client)
The output would be printed on the console.

**Library Usage**

The TestPIR Classes have sample usage for integrating JPIR as library into your applications.
