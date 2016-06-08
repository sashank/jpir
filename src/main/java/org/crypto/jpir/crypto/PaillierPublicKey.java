package org.crypto.jpir.crypto;

import java.math.BigInteger;
import java.security.PublicKey;

/*
*
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
*    PaillierPublicKey is added by Sashank Dara (sashank.dara@gmail.com).
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
public class PaillierPublicKey implements PublicKey {
    private BigInteger n;
    private transient BigInteger n2;

    public PaillierPublicKey(BigInteger n) {this.n=n; n2 = n.multiply(n);}

    public BigInteger getN() {
        return n;
    }

    public BigInteger getN2() {
        return n2;
    }

    @Override
    public String getAlgorithm() {
        return "Paillier";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
