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

import org.crypto.jpir.crypto.HE;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class PIRClient implements PIRClient_Intf {
	private KeyPair keypair;
	
	private HE homEnc;
	private int width, dbSize, queryDim , querySize;

	public PIRClient(HE homEnc, int width, int size) {
		this.homEnc = homEnc;
		keypair = homEnc.getKeyPair();
		this.width = width;
        this.dbSize = size;
        queryDim = 2;
        querySize = (int)Math.round(Math.ceil(Math.pow(dbSize, 1.0 / queryDim)));
	}

    public int getQueryDim() {
        return queryDim;
    }

    public int getQuerySize() {
        return querySize;
    }

    @Override
    public PublicKey getPublicKey() {
        return keypair.getPublic();
    }

    @Override
    public PrivateKey getPrivateKey() {
        return keypair.getPrivate();
    }

	/**
	 *  Generate Query requires generating a uni-dimensional vector
	 *  consisting of encryption of 1 in index position
	 *  and encryption of 0's in remaining places.
     *
     *  The length of the vector should be squareroot of database dbSize
     *
     *  Although below code is generic, it is tested for only two dimensional
     *  databases and uni dimensional input vectors.
     *
	 */

    public ArrayList<BigInteger> generateQueryVector(int index) {
		if (homEnc == null)
			return null;

		ArrayList<BigInteger> queryValues = new ArrayList<>(queryDim - 1);
		for (int i = 0; i < queryDim - 1; i++) {
			int nonzero = index % querySize;
			for (int j = 0; j < querySize; j++) {
				queryValues.add(homEnc.encrypt(j == nonzero ? BigInteger.ONE : BigInteger.ZERO));
			}
			index = index / querySize;
		}

		return queryValues;
	}

    public ArrayList<BigInteger> generateIndexVector(int index){
        if (homEnc == null)
            return null;

        ArrayList<BigInteger> queryValues = new ArrayList<>(queryDim - 1);
        for (int i = 0; i < queryDim - 1; i++) {
            int nonzero = index % querySize;
            for (int j = 0; j < querySize; j++) {
                queryValues.add( j == nonzero ? BigInteger.ONE : BigInteger.ZERO);
            }
            index = index / querySize;
        }

        return queryValues;
    }
	public ArrayList<BigInteger> processResponseVector(ArrayList<BigInteger> responseVector){
         ArrayList<BigInteger> resultVector = new ArrayList<>(querySize);
         for(BigInteger response: responseVector)
             resultVector.add(homEnc.decrypt(response)) ;
         return resultVector;
    }
	public BigInteger extractResponse(ArrayList<BigInteger> responseVector, int index) {
	    return processResponseVector(responseVector).get(index);
	}

	@Override
	public int getWidth() {
        int realWidth = homEnc.getDomain().bitLength() - 1;
        if (realWidth < width)
            width = realWidth;

		return width;
	}
}
