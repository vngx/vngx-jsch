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

package org.vngx.jsch.kex;

import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.HashManager;

/**
 * Implementation of {@code KeyExchange} for
 * "diffie-hellman-group-exchange-sha256" key exchange for SSH.
 *
 * The "diffie-hellman-group-exchange-sha56" method specifies Diffie-Hellman
 * Group and Key Exchange with SHA-256 [FIPS-180-2] as HASH.
 *
 * The server keeps a list of safe primes and corresponding generators that it
 * can select from.  A prime p is safe if p = 2q + 1 and q is prime.  New primes
 * can be generated in the background.
 *
 * The generator g should be chosen such that the order of the generated
 * subgroup does not factor into small primes; that is, with p = 2q + 1, the
 * order has to be either q or p - 1.  If the order is p - 1, then the exponents
 * generate all possible public values, evenly distributed throughout the range
 * of the modulus p, without cycling through a smaller subset.  Such a generator
 * is called a "primitive root" (which is trivial to find when p is "safe").
 * 
 * The client requests a modulus from the server indicating the preferred size.
 * In the following description (C is the client, S is the server, the modulus
 * p is a large safe prime, and g is a generator for a subgroup of GF(p), min is
 * the minimal size of p in bits that is acceptable to the client, n is the size
 * of the modulus p in bits that the client would like to receive from the
 * server, max is the maximal size of p in bits that the client can accept, V_S
 * is S's version string, V_C is C's version string, K_S is S's public host key,
 * I_C is C's KEXINIT message, and I_S is S's KEXINIT message that has been
 * exchanged before this part begins):
 *
 *		1.  C sends "min || n || max" to S, indicating the minimal acceptable
 *			group size, the preferred size of the group, and the maximal group
 *			size in bits the client will accept.
 *		2.  S finds a group that best matches the client's request, and sends
 *			"p || g" to C.
 *		3.  C generates a random number x, where 1 &lt; x &lt; (p-1)/2.  It
 *			computes e = g^x mod p, and sends "e" to S.
 *		4.  S generates a random number y, where 0 &lt; y &lt; (p-1)/2, and
 *			computes f = g^y mod p.  S receives "e".  It computes K = e^y mod
 *			p, H = hash(V_C || V_S || I_C || I_S || K_S || min || n || max ||
 *			p || g || e || f || K) (these elements are encoded according to
 *			their types; see below), and signature s on H with its private host
 *			key. S sends "K_S || f || s" to C. The signing operation may involve
 *			a second hashing operation.
 *		5.  C verifies that K_S really is the host key for S (e.g., using
 *			certificates or a local database to obtain the public key).  C is
 *			also allowed to accept the key without verification; however, doing
 *			so will render the protocol insecure against active attacks (but may
 *			be desirable for practical reasons in the short term in many
 *			environments).  C then computes K = f^x mod p, H = hash(V_C || V_S
 *			|| I_C || I_S || K_S || min || n || max || p || g || e || f || K),
 *			and verifies the signature s on H.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class DHGexSha256KexAlgorithm extends DHGexSha1KexAlgorithm {

	public DHGexSha256KexAlgorithm() throws JSchException {
		super(HashManager.getManager().createHash(Hash.HASH_SHA256));
	}

}
