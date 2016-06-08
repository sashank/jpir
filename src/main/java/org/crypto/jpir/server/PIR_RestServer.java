package org.crypto.jpir.server;

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
*    PIR_RestServer is added by Sashank Dara (sashank.dara@gmail.com).
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


import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.crypto.jpir.crypto.HE;
import org.crypto.jpir.crypto.Paillier;
import org.crypto.jpir.util.Settings;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Properties;

import static spark.Spark.get;
import static spark.Spark.post;

public class PIR_RestServer {
    private String port;
    private HE he ;
    private int width;
    private int dbSize,dbDimension;
    private PIRServer server;
    private Properties properties;
    private void init(String preferencesFile) {

        try (InputStream in = new FileInputStream(preferencesFile)) {
            properties = new Properties();
            properties.load(in);

            String cipher = properties.getProperty(Settings.CIPHER);
            int keySize = Integer.valueOf(properties.getProperty(Settings.KEYSIZE));
            SecureRandom rnd = new SecureRandom();
            String publicKeyStr =  properties.getProperty(Settings.PUBLIC_KEY);
            String inputDir = properties.getProperty(Settings.INPUTDIR);
            port = properties.getProperty(Settings.SERVER_PORT);
            dbSize = Integer.valueOf(properties.getProperty(Settings.DBSIZE));
            width = Integer.valueOf(properties.getProperty(Settings.WIDTH));
            // Only two dimensions supported for now.
            dbDimension = (int)Math.round(Math.ceil(Math.pow(dbSize, 1.0 / 2)));

            if(cipher.equals(Settings.PAILLIER)) {
                he = new Paillier(keySize, rnd,publicKeyStr,"");
                server = new PIRServer(he,width,dbSize,inputDir);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }   catch (Exception e) {
            e.printStackTrace();
            System.out.println("Cannot init PIR Rest Server");
            System.exit(0);
        }
    }
    public static void main(String[] args) {
        String preferencesFile = "server.properties"; ;
        if(args.length == 1)
            preferencesFile = args[0];

        PIR_RestServer pirRestServer = new PIR_RestServer();
        pirRestServer.init(preferencesFile);

        Gson gson = new Gson();

        //Basic call - Home page

        get("/pir", (request, response) -> "Private Information Retrieval");

        // Settings
        get("/settings", (request, response) -> {
            response.status(201); // 201 Created
            return gson.toJson(pirRestServer.properties);
        });

        // Get Private Objects By Index/Id
        post("/pobj", (request, response) -> {
            String queryStr = request.body();
            ArrayList<BigInteger> queryVec = new Gson().fromJson(queryStr, (new TypeToken<ArrayList<BigInteger>>(){}.getType()));
            ArrayList<BigInteger> list = pirRestServer.server.processQuery(queryVec);
            response.status(201);
            return gson.toJson(list);
        });


        // Get Objects By Index/Id
        get("/obj", (request, response) -> {
            String queryStr = request.queryParams(Settings.INDEX);
            BigInteger element = pirRestServer.server.getRealItem(Integer.valueOf(queryStr));
            String responseStr = new String(element.toByteArray());
            response.status(201);
            return responseStr;
        });
    }

}