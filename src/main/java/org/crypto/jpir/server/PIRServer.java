package org.crypto.jpir.server;

/*
*    jpir is fork of pir-0.1
*
 *   pir-0.1 is Private Information Retrieval Library in Java
*
*    This was originally developed at Stanford
*
*    By People
*    Dan Boneh, Andrew Bortz, Srinivas Inguva, Felipe Saint-Jean, Joan Feigenbaum
*
*    Original Link
*    https://crypto.stanford.edu/pir-library/
*
*    PIRServer is added by Sashank Dara (sashank.dara@gmail.com).
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

import org.crypto.jpir.crypto.HE;

import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class PIRServer implements PIRServer_Intf {
    private PublicKey publicKey;
    private int maxWidth;
    private HE homEnc;
    private BigInteger matrixDB[][];
    private int dbDimension;
    private String inputFile;
    private ArrayList<String> wordsInFile;
    public PIRServer(HE c, int maxWidth, int size, String inputFile) {
        this.homEnc = c; this.maxWidth = maxWidth;
        this.inputFile = inputFile;
        publicKey = c.getKeyPair().getPublic();
        wordsInFile = new ArrayList<>();
        this.dbDimension = (int)Math.round(Math.ceil(Math.pow(size, 1.0 / 2)));    // Only two dimensions supported for now.
        setMatrixDB(null);
    }

    private void loadWords(){
        try {
            FileInputStream inputStream = new FileInputStream(inputFile);
            Scanner scanner = new Scanner(inputStream);

            while(scanner.hasNextLine()){
                wordsInFile.add(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            System.out.println("Some Exception reading the file"+inputFile);
        }
    }
    public void setMatrixDB(BigInteger[][] matrixDB){

        if(matrixDB == null) {
            loadWords();
            this.matrixDB = new BigInteger[dbDimension][dbDimension];
            for (int i = 0; i < dbDimension; i++)
                for (int j = 0; j <dbDimension ; j++) {
                    String word =  wordsInFile.get(i + j);
                    try {
                        this.matrixDB[i][j] = new BigInteger(word.getBytes("UTF-8"));
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                }
        }
        else
            this.matrixDB = matrixDB;
    }

    @Override
    public ArrayList<BigInteger> processQuery(ArrayList<BigInteger> queryVector){
        if(queryVector.size() > dbDimension)
            return new ArrayList<>();

        ArrayList<BigInteger> responseVector = new ArrayList<>(dbDimension);
        for(int i = 0 ; i < dbDimension ; i++ ) {
            BigInteger response = null ;    // Default
            for (int j = 0 ; j < dbDimension; j++){
                BigInteger c2 = homEnc.multiplyByScalar(queryVector.get(j), matrixDB[j][i]);
                response =  homEnc.add(response , c2);
            }
            responseVector.add(response);
        }
        return  responseVector;
    }

    @Override
    public BigInteger[][] getDB() {
        return matrixDB;
    }

    @Override
    public int getDBDimension() {
        return dbDimension;
    }

    @Override
    public  PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public BigInteger getRealItem(int index) {
        return getRealRow(index).get(index);
    }

    /* For testing purposes */
    public ArrayList<BigInteger> getRealRow(int index){
        ArrayList<BigInteger> realRow  = new ArrayList<>(dbDimension);
        realRow.addAll(Arrays.asList(matrixDB[index]).subList(0, dbDimension));
        return realRow;
    }
}
