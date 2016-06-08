package org.crypto.jpir.util;

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

import java.math.BigInteger;
import java.security.SecureRandom;

public class BigIntegerUtils {
	public static BigInteger randomInterval(BigInteger max, SecureRandom rnd) {
		int bits = max.bitLength() + 1;
		BigInteger k = null;
		do {
			k = new BigInteger(bits, rnd);
		} while (k.compareTo(max) >= 0);
		
		return k;
	}
	
	public static boolean isValidFactorization(BigInteger factor[], int multiple[]) {
		if (factor.length == 0 || factor.length != multiple.length)
			return false;
		
		for (int i = 0; i < factor.length; i++) {
			if (!factor[i].isProbablePrime(100) || multiple[i] <= 0)
				return false;
			
			for (int j = 0; j < i; j++) {
				if (factor[i].equals(factor[j]))
					return false;
			}
		}
		
		return true;
	}
	
	public static int jacobi(BigInteger a, BigInteger n) {
		int cs = 1;
		
		while (true) {
			if (a.equals(BigInteger.ZERO))
				return cs*0;
			else if (a.equals(BigInteger.ONE))
				return cs*1;
			
			int e = a.getLowestSetBit();
			BigInteger a2 = a.shiftRight(e);
			
			int s = 1;
			if (e % 2 != 0) {
				BigInteger r = n.and(BigInteger.valueOf(7));
				if (r.equals(BigInteger.valueOf(3)) || r.equals(BigInteger.valueOf(5)))
					s = -1;
			}
			
			if ( n.and(BigInteger.valueOf(3)).equals(BigInteger.valueOf(3)) &&
				a2.and(BigInteger.valueOf(3)).equals(BigInteger.valueOf(3))) {
				s = -s;
			}
			
			if (a2.equals(BigInteger.valueOf(1)))
				return cs*s;
			
			BigInteger n2 = n.mod(a2);
			
			a = n2;
			n = a2;
			cs = cs * s;
		}
	}
	
	public static int log(BigInteger r, BigInteger d) {
		int e = 0;
		while (r.compareTo(BigInteger.ZERO) > 0) {
			r = r.divide(d);
			e++;
		}
		
		return e;
	}
	
	public static int pow(int b, int e) {
		int r = 1;
		while (e > 0) {
			if ((e & 1) == 1)
				r = r * b;
			b = b * b;
			e = e >> 1;
		}
		
		return r;
	}
}