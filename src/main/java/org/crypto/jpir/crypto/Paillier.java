package org.crypto.jpir.crypto;

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

import org.crypto.jpir.util.BigIntegerUtils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;

public class Paillier implements HE {
		
	private static BigInteger L(BigInteger x, BigInteger n) {
		return x.subtract(BigInteger.ONE).divide(n);
	}
	private KeyPair keyPair ;
	private int keySize;
	private transient SecureRandom rnd;
	
	public Paillier(int keySize, SecureRandom rnd) {this.keySize = keySize; this.rnd = rnd; keyGen();}
	public Paillier(int keySize, SecureRandom rnd,String publicKeyStr, String privateKeyStr) {
		this.keySize = keySize;
        this.rnd = rnd;
        PaillierPublicKey publicKey;
        PaillierPrivateKey privateKey;

        BigInteger publicKeyN = new BigInteger(publicKeyStr);
        publicKey = new PaillierPublicKey(publicKeyN);
        if(privateKeyStr == null || privateKeyStr.equals(""))
            privateKey = new PaillierPrivateKey(BigInteger.ONE,BigInteger.ONE) ; // Dummy Key
        else
            privateKey = new PaillierPrivateKey(new BigInteger(privateKeyStr),new BigInteger(publicKeyStr));

        keyPair = new KeyPair(publicKey,privateKey);
        setKeyPair(keyPair);
    }

	public String toString() {return "Paillier, keySize=" + keySize;}

    private void keyGen() {
        BigInteger p = null, q = null, n = null;
        do {
            p = BigInteger.probablePrime(keySize /2+1, rnd);
            q = BigInteger.probablePrime(keySize -(keySize /2), rnd);
            n = p.multiply(q);
        } while (n.bitLength() != keySize +1);

        BigInteger pm1 = p.subtract(BigInteger.ONE);
        BigInteger qm1 = q.subtract(BigInteger.ONE);
        BigInteger phi = pm1.multiply(qm1);
        BigInteger l = phi.divide(pm1.gcd(qm1));

        keyPair = new KeyPair(new PaillierPublicKey(n), new PaillierPrivateKey(l,n));

    }
	public KeyPair getKeyPair() {
        if(keyPair == null)
             keyGen();

		return keyPair;
	}

    public BigInteger encrypt(BigInteger P) {
		PaillierPublicKey key = (PaillierPublicKey)keyPair.getPublic() ;
		
		BigInteger r = BigIntegerUtils.randomInterval(key.getN(), rnd);
		
		BigInteger c = P.multiply(key.getN()).add(BigInteger.ONE).multiply(r.modPow(key.getN(), key.getN2())).mod(key.getN2());
		return c;
	}
	
	public BigInteger getDomain() {
		return ((PaillierPublicKey)keyPair.getPublic()).getN();
	}
	
	public BigInteger getRange() {
		return ((PaillierPublicKey)keyPair.getPublic()).getN2();
	}

	@Override
    public void setKeyPair(KeyPair pair) {
        this.keyPair = pair;
    }

    public BigInteger decrypt(BigInteger C) {
		PaillierPrivateKey key = (PaillierPrivateKey) keyPair.getPrivate();
		BigInteger m = L(C.modPow(key.getL(), key.getN2()), key.getN()).multiply(L(key.getL().multiply(key.getN())
				.add(BigInteger.ONE), key.getN()).modInverse(key.getN())).mod(key.getN());
		return m;
	}
	
	public BigInteger add(BigInteger C1, BigInteger C2) {
		PaillierPublicKey key = (PaillierPublicKey)keyPair.getPublic() ;
        if(C1 == null)
            C1 = BigInteger.ONE;
        if(C2 == null)
            C2 = BigInteger.ONE;
		return C1.multiply(C2).mod(key.getN2());
	}
    public BigInteger substract(BigInteger C1, BigInteger C2) {
		PaillierPublicKey key = (PaillierPublicKey)keyPair.getPublic() ;
        if(C1 == null)
            C1 = BigInteger.ONE;
        if(C2 == null)
            C2 = BigInteger.ONE;

        // Calculate Multiplicative Inverse
        BigInteger C2Inverse = C2.modPow(new BigInteger("-1"),key.getN2());

		return add(C1,C2Inverse);
	}
	
	public BigInteger multiplyByScalar(BigInteger C1, BigInteger m) {
		PaillierPublicKey key = (PaillierPublicKey)keyPair.getPublic() ;
		return C1.modPow(m, key.getN2());
	}

    public BigInteger multiply(BigInteger C1, BigInteger C2) {
        return BigInteger.ZERO; // Not Supported
    }
}
