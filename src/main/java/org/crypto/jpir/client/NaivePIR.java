package org.crypto.jpir.client;

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

import org.crypto.jpir.server.PIRServer_Intf;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

public class NaivePIR implements PIRClient_Intf,PIRServer_Intf {

	private BigInteger[][] matrixDB;
	private int dbDimension, width;
	private SecureRandom secureRandom;

    public NaivePIR(int size, int width, SecureRandom secureRandom) {
		this.width = width;
		this.secureRandom = secureRandom;
        this.dbDimension = (int)Math.round(Math.ceil(Math.pow(size, 1.0 / 2)));
		setMatrixDB(null);
    }


    public void setMatrixDB(BigInteger[][] matrixDB){

        if(matrixDB == null) {
            this.matrixDB = new BigInteger[dbDimension][dbDimension];
            for (int i = 0; i < dbDimension; i++)
                for (int j = 0; j <dbDimension ; j++)
                    this.matrixDB[i][j] = new BigInteger(width, secureRandom);
        }
        else
            this.matrixDB = matrixDB;
    }
    @Override
	public BigInteger extractResponse(ArrayList<BigInteger> responseVector, int index) {
		return (BigInteger)(responseVector).get(index);
	}

    @Override
    public int getWidth() {
        return width;
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
	public PublicKey getPublicKey() {
		return null;
	}

	@Override
	public ArrayList<BigInteger> processQuery(ArrayList<BigInteger> queryValues) {
		for(int i=0 ; i < queryValues.size(); i++)
            if(queryValues.get(i).equals(BigInteger.ONE))
                return getRealRow(i);
        return new ArrayList<>();
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

    @Override
	public PrivateKey getPrivateKey() {
		return null;
	}

    @Override
    public ArrayList<BigInteger> generateQueryVector(int index) {
        ArrayList<BigInteger> queryVector = new ArrayList<>(dbDimension);
        for(int i= 0 ; i < dbDimension; i++)
            if(i == index)
                queryVector.add(BigInteger.ONE);
            else
                queryVector.add(BigInteger.ZERO);

        return queryVector;
    }


}
