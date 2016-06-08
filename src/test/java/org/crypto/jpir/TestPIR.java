package org.crypto.jpir;

/*
*    jpir is fork of pir-0.1
*
*    pir-0.1 is Private Information Retrieval Library in Java
*
*    This was originally developed at Stanford
*
*    By People
*    Dan Boneh, Andrew Bortz, Srinivas Inguva, Felipe Saint-Jean, Joan Feigenbaum
*
*    Original Link
*    https://crypto.stanford.edu/pir-library/
*
*    Refactored by Sashank Dara
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/

import junit.framework.TestCase;
import org.crypto.jpir.crypto.HE;
import org.crypto.jpir.crypto.Paillier;
import org.crypto.jpir.client.NaivePIR;
import org.crypto.jpir.client.PIRClient;
import org.crypto.jpir.crypto.PaillierPrivateKey;
import org.crypto.jpir.crypto.PaillierPublicKey;
import org.crypto.jpir.server.PIRServer;
import org.crypto.jpir.util.Settings;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Properties;


public class TestPIR extends TestCase {

    private int width;
    private int dbSize;
    private int keySize;
    private int dbDimension;
    private HE he;
    private String inputFile ;
    private Properties clientProperties,serverProperties;

    public void setUp() throws Exception {
        super.setUp();
        inputFile = "in/words.txt";
        init();
        dbSize = Integer.valueOf(clientProperties.getProperty(Settings.DBSIZE));
        width = Integer.valueOf(clientProperties.getProperty(Settings.WIDTH));
        keySize = Integer.valueOf(clientProperties.getProperty(Settings.KEYSIZE));
    }

    public void testPallier() throws Exception {
        SecureRandom rnd = new SecureRandom();
        HE p_he = new Paillier(keySize, rnd);

        // Test By Index
        testPIRByIndex(p_he);


        NaivePIR naivePIR = new NaivePIR(dbSize,width,rnd);
        testPIRByIndex(naivePIR);
    }

    public void testPIRGenerateQueryVector() throws Exception{
        SecureRandom rnd = new SecureRandom();
        HE p_he = new Paillier(keySize, rnd);
        testGenerateQuery(p_he);
    }

    public void testPIRGenerateResponseVector() throws Exception{
        SecureRandom rnd = new SecureRandom();
        HE p_he = new Paillier(keySize, rnd);
        testGenerateResponse(p_he);
    }


    private void testGenerateResponse(HE he) throws Exception{

        PIRClient pirClient = new PIRClient(he, width, dbSize);
        PIRServer pirServer = new PIRServer(he, width, dbSize, inputFile);

        int index = 2;
        ArrayList<BigInteger> indexVector = pirClient.generateIndexVector(index);
        ArrayList<BigInteger> queryVector = pirClient.generateQueryVector(index);
        pirServer.setMatrixDB(null);

        ArrayList<BigInteger> responseVector = pirServer.processQuery(queryVector);
        ArrayList<BigInteger> responseValues = pirClient.processResponseVector(responseVector);

        ArrayList<BigInteger> realValues = pirServer.getRealRow(index);

        if(realValues.equals(responseValues))
            assertTrue("Vector Multiplication Works", true);
        else
            assertTrue("Vector Multiplication Fails", false);

    }


    private void testGenerateQuery(HE p_he) {
        PIRClient pirClient = new PIRClient(p_he, width, dbSize);

        for(int index = 0; index < pirClient.getQuerySize() ; index++) {
            ArrayList<BigInteger> queryVector = pirClient.generateQueryVector(index);
            ArrayList<BigInteger> indexVector = pirClient.generateIndexVector(index);
            ArrayList<BigInteger> decryptVector = getIndexVector(p_he, queryVector);
            if (indexVector.equals(decryptVector))
                assertTrue("Generate Query Works", true);
            else
                assertTrue("Generate Query Does not Work", false);
        }
    }
    private ArrayList<BigInteger> getIndexVector(HE he , ArrayList<BigInteger> queryVector) {
        ArrayList<BigInteger> indexVector = new ArrayList<>(queryVector.size());
        for(BigInteger integer: queryVector)
            indexVector.add(he.decrypt(integer));
        return indexVector;
    }

    private void testPIRByIndex(HE homEnc) {
        PIRClient pirClient = new PIRClient(homEnc, width, dbSize);
        PIRServer pirServer = new PIRServer(homEnc, width, dbSize,inputFile);
        dbDimension = pirServer.getDBDimension();
        for (int index = 0; index < dbDimension; index++) {
            ArrayList<BigInteger> queryItems = pirClient.generateQueryVector(index);
            ArrayList<BigInteger> responseItems = pirServer.processQuery(queryItems);
            BigInteger resultItem = pirClient.extractResponse(responseItems, index);
            BigInteger realItem = pirServer.getRealItem(index);
            String resultStr = new String(resultItem.toByteArray());
            String realStr = new String(realItem.toByteArray());
            System.out.println("Real String " + realStr +" Result String " + resultStr);
            assertTrue("PIR Retrieval Status", resultItem.equals(realItem));
        }
    }
    private void testPIRByIndex(NaivePIR naivePIR) {
        NaivePIR pirClient = naivePIR;
        NaivePIR pirServer = naivePIR;
        dbDimension = pirServer.getDBDimension();
        for (int index = 0; index < dbDimension; index++) {
            ArrayList<BigInteger> queryItems = pirClient.generateQueryVector(index);
            ArrayList<BigInteger> responseItems = pirServer.processQuery(queryItems);
            BigInteger resultItem = pirClient.extractResponse(responseItems, index);
            BigInteger realItem = pirServer.getRealItem(index);
            assertTrue("PIR Retrieval Status", resultItem.equals(realItem));
        }
    }

    private void init() {
        keySize = 1024;
        SecureRandom rnd = new SecureRandom();
        he = new Paillier(keySize, rnd);
        PaillierPublicKey publicKey = (PaillierPublicKey) he.getKeyPair().getPublic();
        PaillierPrivateKey privateKey = (PaillierPrivateKey) he.getKeyPair().getPrivate();

        // load the client preferences
        try (InputStream in = new FileInputStream("client.properties")) {
            clientProperties = new Properties();
            clientProperties.load(in);

        } catch (IOException e) {
            // If does not exist create one
            try (OutputStream out = new FileOutputStream("client.properties")) {
                clientProperties = new Properties();
                clientProperties.setProperty(Settings.CIPHER, Settings.PAILLIER);
                clientProperties.setProperty(Settings.KEYSIZE, String.valueOf( 1024));
                clientProperties.setProperty(Settings.PUBLIC_KEY, publicKey.getN().toString());
                clientProperties.setProperty(Settings.PRIVATE_KEY, privateKey.getL().toString());
                clientProperties.setProperty(Settings.INPUTDIR, inputFile);
                clientProperties.setProperty(Settings.DBSIZE, "9");
                clientProperties.setProperty(Settings.WIDTH, "4");
                clientProperties.setProperty(Settings.SERVER_IP, "0.0.0.0"); // Gcloud Server
                clientProperties.setProperty(Settings.SERVER_PORT, "4567");
                clientProperties.store(out,"PPTI Client Preferences");

            } catch (IOException ioException) {
                e.printStackTrace();
            }
        }


        try (InputStream in = new FileInputStream("server.properties")) {
            serverProperties = new Properties();
            serverProperties.load(in);

        } catch (IOException serverIo) {
           // e.printStackTrace();
            try (OutputStream out = new FileOutputStream("server.properties")) {
                serverProperties = new Properties();
                serverProperties.setProperty(Settings.CIPHER, Settings.PAILLIER);
                serverProperties.setProperty(Settings.KEYSIZE, String.valueOf(1024));
                serverProperties.setProperty(Settings.PUBLIC_KEY, publicKey.getN().toString());
                serverProperties.setProperty(Settings.INPUTDIR, inputFile);
                serverProperties.setProperty(Settings.DBSIZE, "9");
                serverProperties.setProperty(Settings.WIDTH, "4");
                serverProperties.setProperty(Settings.SERVER_PORT, "4567");
                serverProperties.store(out,"PPTI Server Preferences");

            } catch (IOException serverIoException) {
                serverIoException.printStackTrace();
            }
        }
    }
}
