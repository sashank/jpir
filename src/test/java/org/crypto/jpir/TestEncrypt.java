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
import org.crypto.jpir.crypto.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;

public class TestEncrypt extends TestCase{

    private void testPK(PKE c) {
        SecureRandom random = new SecureRandom() ;
        System.out.println("Testing PK:\n" + c);

        KeyPair pair = c.getKeyPair();

        int bits = c.getDomain().bitLength() - 1;

        BigInteger P = new BigInteger(bits, random);
        BigInteger C = c.encrypt(P);

        BigInteger P2 = c.decrypt(C);
        System.out.println("P " + P);
        System.out.println("C " + C);
        System.out.println("P2 " + P2);
        if (P2.equals(P))
            assertTrue("Encryption Works" , true);
        else
            assertTrue("Encryption Fails" , false);

    }


    private  void testAddHomomorphic(HE c) {
        SecureRandom random = new SecureRandom() ;
        System.out.println("Testing Additive Homomorphism:\n" + c);

        KeyPair pair = c.getKeyPair();
        int bits = c.getDomain().bitLength() - 1;

        BigInteger P1 = new BigInteger(bits, random);;
        BigInteger C1 = c.encrypt(P1);
        BigInteger P2 = new BigInteger(bits, random);
        BigInteger C2 = c.encrypt(P2);

        BigInteger C3 = c.add(C1, C2);

        BigInteger P3 = c.decrypt(C3);
        System.out.println("P1 " + P1);
        System.out.println("C1 " + C1);
        System.out.println("P2 " + P2);
        System.out.println("C2 " + C2);
        System.out.println("P3 " + P3);

        if (P3.equals(P1.add(P2).mod(c.getDomain())))
            assertTrue("Homomorphic Addition Works" , true);
        else
            assertTrue("Homomorphic Addition Fails" , false);

    }

    private  void testMultHomomorphic(HE c) {
        SecureRandom random = new SecureRandom() ;
        System.out.println("Testing Multiplicative Homomorphism:\n" + c);

        KeyPair pair = c.getKeyPair();
        int bits = c.getDomain().bitLength() - 1;

        BigInteger P1 = new BigInteger(bits, random);;
        BigInteger C1 = c.encrypt(P1);
        BigInteger P2 = new BigInteger(bits, random);
        BigInteger C2 = c.encrypt(P2);

        BigInteger C3 = c.multiply(C1, C2);

        BigInteger P3 = c.decrypt(C3);
        System.out.println("P1 " + P1);
        System.out.println("C1 " + C1);
        System.out.println("P2 " + P2);
        System.out.println("C2 " + C2);
        System.out.println("P3 " + P3);

        if (P3.equals(P1.multiply(P2).mod(c.getDomain())))
            assertTrue("Homomorphic Multiplication Works" , true);
        else
            assertTrue("Homomorphic Multiplication Fails" , false);

    }

    /*
       This is to test
         P1 * P2 + P3 * P4 = Dec (HOM_Enc(P1) * P2 + HOM_Enc(P3) * P4)
     */
    private void testAddAndMultHomomorphic(HE c){
        SecureRandom random = new SecureRandom() ;
        System.out.println("Testing Add and Multiply By Constant Homomorphism:\n" + c);

        KeyPair pair = c.getKeyPair();
        int bits = c.getDomain().bitLength() - 1;

        BigInteger P1 = new BigInteger("1234");
        BigInteger P2 = new BigInteger("2345");
        BigInteger P3 = new BigInteger("4567");
        BigInteger P4 = new BigInteger("5678");

        System.out.println("P1 " + P1);
        System.out.println("P2 " + P2);
        System.out.println("P3 " + P3);
        System.out.println("P4 " + P4);

        BigInteger C1 = c.encrypt(P1);
        BigInteger C3 = c.encrypt(P3);

        BigInteger C1xP2 = c.multiplyByScalar(C1, P2);

        final BigInteger firstmult = P1.multiply(P2).mod(c.getDomain());
        final BigInteger firstdecr = c.decrypt(C1xP2);

        System.out.println("Firstmult            " + firstmult);
        System.out.println("Firstmult (decr)     " + firstdecr );

        if ((firstmult).equals(firstdecr))
            assertTrue("Homomorphic Add and Multiplication By Constant Works" , true);
        else
            assertTrue("Homomorphic Add and Multiplication By Constant Fails" , false);

        BigInteger C3xP4 = c.multiplyByScalar(C3, P4);

        final BigInteger secMult = P3.multiply(P4).mod(c.getDomain());
        final BigInteger secDecr = c.decrypt(C3xP4);

        System.out.println("SecMult            " + secMult);
        System.out.println("Secmult (decr)     " + secDecr);


        if (secMult.equals(secDecr))
            assertTrue("Homomorphic Add and Multiplication By Constant Works" , true);
        else
            assertTrue("Homomorphic Add and Multiplication By Constant Fails" , false);

        BigInteger encsum = c.add(C1xP2,C3xP4);

        BigInteger sum = c.decrypt(encsum);
        BigInteger realsum = firstmult.add(secMult);

        System.out.println("sum     " + sum);
        System.out.println("realsum " + realsum);

        if (realsum.equals(sum))
            assertTrue("Homomorphic Add and Multiplication By Constant Works" , true);
        else
            assertTrue("Homomorphic Add and Multiplication By Constant Fails" , false);
    }

    private void testMultByConstantHE(HE c){
        SecureRandom random = new SecureRandom() ;
        System.out.println("Testing Mult Homomorphism by Constant:\n" + c);

        KeyPair pair = c.getKeyPair();
        int bits = c.getDomain().bitLength() - 1;

        BigInteger P1 = new BigInteger(bits, random);;
        BigInteger C1 = c.encrypt(P1);
        BigInteger P2 = new BigInteger(bits, random);

        BigInteger C3 = c.multiplyByScalar(C1, P2);

        BigInteger P3 = c.decrypt(C3);

        System.out.println("P1 " + P1);
        System.out.println("C1 " + C1);
        System.out.println("P2 " + P2);
        System.out.println("C2 " + C3);
        System.out.println("P3 " + P3);

        if (P3.equals(P1.multiply(P2).mod(c.getDomain())))
            assertTrue("Homomorphic Multiplication By Constant Works" , true);
        else
            assertTrue("Homomorphic Multiplication By Constant Fails" , false);

    }
   /*
    public void testGM() throws Exception {
        SecureRandom rnd = new SecureRandom();
        HE c = new GoldwasserMicali(1024, rnd);
        testAll(c);
    }  */
    public void testPaillier() throws Exception  {
        SecureRandom rnd = new SecureRandom();
        HE c = new Paillier(1024, rnd);
        testAll(c);
    }

    private void testAll(HE c) {
        testPK(c);
        testAddHomomorphic(c);
      //  testMultHomomorphic(c);  // Not Supported
        testMultByConstantHE(c);
        testAddAndMultHomomorphic(c);
    }

  /*  public void testElGamal()throws Exception  {
        HE c = null;
            ElGamal elGamal = new ElGamal();
            testPK(elGamal);
            //testPKBytes(elGamal);
            // testAddHomomorphic(elGamal);


    } */
}