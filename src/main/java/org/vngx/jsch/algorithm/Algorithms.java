/*
 * Copyright (c) 2010-2011 Michael Laudati, N1 Concepts LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL N1
 * CONCEPTS LLC OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch.algorithm;

import org.vngx.jsch.userauth.UserAuth;

/**
 * <p>Constant algorithm names for retrieving implementations from the
 * {@code AlgorithmManager} instance.  The constant names can also be used
 * for overriding implementations in the {@code JSchConfig} instance or
 * {@code SessionConfig} instances.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4250">RFC4250 - The Secure
 * Shell (SSH) Protocol Assigned Numbers</a></p>
 *
 * @see org.vngx.jsch.algorithm.AlgorithmManager
 * @see org.vngx.jsch.config.JSchConfig
 *
 * @author Michael Laudati
 */
public interface Algorithms {

	/** 
	 * Algorithm name {@value} for instances of {@code DiffieHellman}.
	 * 
	 * @see org.vngx.jsch.kex.DiffieHellman
	 */
	String DIFFIE_HELLMAN = "diffie-hellman";
	/**
	 * Algorithm name {@value} for instances of {@code Random}.
	 *
	 * @see org.vngx.jsch.algorithm.Random
	 */
	String RANDOM = "random";

	/** 
	 * Algorithm name {@value} for "diffie-hellman-group1-sha1"
	 * {@code KexAlgorithm}.
	 * <p>
	 * The "diffie-hellman-group1-sha1" method specifies the Diffie-Hellman key 
	 * exchange with SHA-1 as HASH, and Oakley Group 2 [RFC2409] (1024-bit MODP 
	 * Group).  This method MUST be supported for interoperability as all of the 
	 * known implementations currently support it.
	 * 
	 * @see org.vngx.jsch.kex.KexAlgorithm
	 */
	String DIFFIE_HELLMAN_GROUP1_SHA1 = "diffie-hellman-group1-sha1";
	/**
	 * Algorithm name {@value} for 'diffie-hellman-group14-sha1'
	 * {@code KexAlgorithm}.
	 * <p>
	 * The "diffie-hellman-group14-sha1" method specifies a Diffie-Hellman key 
	 * exchange with SHA-1 as HASH and Oakley Group 14 [RFC3526] (2048-bit MODP 
	 * Group), and it MUST also be supported.
	 * 
	 * @see org.vngx.jsch.kex.KexAlgorithm
	 */
	String DIFFIE_HELLMAN_GROUP14_SHA1 = "diffie-hellman-group14-sha1";
	/**
	 * Algorithm name {@value} for 'diffie-hellman-group-exchange-sha1'
	 * {@code KexAlgorithm}.
	 * <p>
	 * The "diffie-hellman-group-exchange-sha1" method specifies Diffie-Hellman
	 * Group and Key Exchange with SHA-1 [FIPS-180-2] as hash.
	 *
	 * @see org.vngx.jsch.kex.KexAlgorithm
	 */
	String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 = "diffie-hellman-group-exchange-sha1";
	/**
	 * Algorithm name {@value} for 'diffie-hellman-group-exchange-sha256'
	 * {@code KexAlgorithm}.
	 * <p>
	 * The "diffie-hellman-group-exchange-sha256" method specifies Diffie-
	 * Hellman Group and Key Exchange with SHA-256 [FIPS-180-2] as hash.
	 *
	 * @see org.vngx.jsch.kex.KexAlgorithm
	 */
	String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256	= "diffie-hellman-group-exchange-sha256";

	String USERAUTH = "userauth.";
	String USERAUTH_NONE			= USERAUTH + UserAuth.NONE;
	String USERAUTH_PASSWORD		= USERAUTH + UserAuth.PASSWORD;
	String USERAUTH_KB_INTERACTIVE	= USERAUTH + UserAuth.KEYBOARD_INTERACTIVE;
	String USERAUTH_PUBLICKEY		= USERAUTH + UserAuth.PUBLICKEY;
	String USERAUTH_GSSAPI_MIC		= USERAUTH + UserAuth.GSSAPI_WITH_MIC;
	String GSSAPI_WITH_MIC_KRB5		= "gssapi-with-mic.krb5";

	/**
	 * Algorithm name {@value} for instances of {@code SignatureDSA}.
	 *
	 * @see org.vngx.jsch.algorithm.SignatureDSA
	 */
	String SIGNATURE_DSS	= "signature.dss";
	/**
	 * Algorithm name {@value} for instances of {@code SignatureRSA}.
	 *
	 * @see org.vngx.jsch.algorithm.SignatureRSA
	 */
	String SIGNATURE_RSA	= "signature.rsa";
	/**
	 * Algorithm name {@value} for instances of {@code KeyPairGenDSA}.
	 *
	 * @see org.vngx.jsch.algorithm.KeyPairGenDSA
	 */
	String KEYPAIRGEN_DSA	= "keypairgen.dsa";
	/**
	 * Algorithm name {@value} for instances of {@code KeyPairGenRSA}.
	 *
	 * @see org.vngx.jsch.algorithm.KeyPairGenRSA
	 */
	String KEYPAIRGEN_RSA	= "keypairgen.rsa";

}
