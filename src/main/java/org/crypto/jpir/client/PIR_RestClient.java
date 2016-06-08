package org.crypto.jpir.client;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
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
*    PIR_RestClient is added by Sashank Dara.
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
public class PIR_RestClient {
    private  Properties preferences;
    private String pirServer;
    private  HE he ;
    private int width;
    private int dbSize,dbDimension;
    private PIRClient pirClient;

    public PIR_RestClient(String preferencesFile) throws Exception {
        init(preferencesFile);
    }

    private void init(String preferencesFile) throws Exception{
        preferences = new Properties();
        try (InputStream in = new FileInputStream(preferencesFile)) {
            preferences.load(in);
        } catch (IOException e) {
            e.printStackTrace();
        }

        SecureRandom rnd = new SecureRandom();
        int keySize =  Integer.valueOf(preferences.getProperty(Settings.KEYSIZE));
        String cipher = preferences.getProperty(Settings.CIPHER);
        String serverIp = preferences.getProperty(Settings.SERVER_IP);
        String serverPort = preferences.getProperty(Settings.SERVER_PORT);
        pirServer =   "http://"+ serverIp+ ":"+serverPort +"/" ;
        String publicKeyStr = preferences.getProperty(Settings.PUBLIC_KEY);
        String privateKeyStr = preferences.getProperty(Settings.PRIVATE_KEY);

        dbSize = Integer.valueOf(preferences.getProperty(Settings.DBSIZE));
        width = Integer.valueOf(preferences.getProperty(Settings.WIDTH));

        // Only two dimensions supported for now.
        dbDimension = (int)Math.round(Math.ceil(Math.pow(dbSize, 1.0 / 2)));

        // Create HE object
        he = new Paillier(keySize, rnd,publicKeyStr,privateKeyStr);
        pirClient = new PIRClient(he,width,dbSize);
    }
    public static void main(String args[]) throws Exception {
        String preferencesFile = "client.properties"; ;
        if(args.length == 1)
            preferencesFile = args[0];

        Gson gson = new Gson();
        PIR_RestClient pirRestClient = new PIR_RestClient(preferencesFile);
        HttpResponse<String> response = Unirest.get( pirRestClient.pirServer + "pir").asString();
        System.out.println(response.getBody());

        for (int index = 0; index < pirRestClient.dbDimension; index++) {
            ArrayList<BigInteger> queryItems = pirRestClient.pirClient.generateQueryVector(index);
            String json = gson.toJson(queryItems,(new TypeToken<ArrayList<BigInteger>>(){}.getType()));
            HttpResponse<String> responseItems = Unirest.post( pirRestClient.pirServer + "pobj")
                                    .body(json)
                                    .asString();

            Gson responseGson = new Gson();
            ArrayList<BigInteger> responseVector =
            responseGson.fromJson(responseItems.getBody(),(new TypeToken<ArrayList<BigInteger>>(){}.getType()));
            BigInteger resultItem = pirRestClient.pirClient.extractResponse(responseVector, index);

            HttpResponse<String> stringHttpResponse = Unirest.get(pirRestClient.pirServer + "obj")
                                            .queryString(Settings.INDEX,index).asString();

            System.out.println("Query " +index + " With Privacy " + new String(resultItem.toByteArray()));
            System.out.println("Query " +index + " Without Privacy " + stringHttpResponse.getBody());
        }


    }
}