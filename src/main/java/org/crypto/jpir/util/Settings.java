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
*    Settings is added by Sashank Dara.
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

public class Settings {

    public static final String KEYSIZE     = "keysize";
    public static final String CIPHER      = "cipher";
    public static final String PUBLIC_KEY  = "pubkey";
    public static final String PRIVATE_KEY = "privkey";
    public static final String PAILLIER    = "Paillier";
    public static final String WIDTH    = "width";
    public static final String DBSIZE    = "dbsize";
    public static final String INPUTDIR    = "inputdir";
    public static final String SERVER_IP   = "serverip";
    public static final String SERVER_PORT = "serverport";
    public static final String INDEX = "index";


    public Settings() {

    }
}
