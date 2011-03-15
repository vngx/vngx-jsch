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

import org.vngx.jsch.algorithm.Algorithm;

/**
 * <p>Interface to define a Diffie-Hellman (DH) key exchange. Diffie–Hellman key
 * exchange is a cryptographic protocol that allows two parties that have no
 * prior knowledge of each other to jointly establish a shared secret key over
 * an insecure communications channel. This key can then be used to encrypt
 * subsequent communications using a symmetric key cipher. It is a type of key
 * exchange.</p>
 *
 * <p>The Diffie-Hellman (DH) key exchange provides a shared secret that cannot
 * be determined by either party alone.  The key exchange is combined with a
 * signature with the host key to provide host authentication.  This key
 * exchange method provides explicit server authentication.</p>
 *
 * <p>The following steps are used to exchange a key.  In this, C is the client;
 * S is the server; p is a large safe prime; g is a generator for a subgroup of
 * GF(p); q is the order of the subgroup; V_S is S's identification string;
 * V_C is C's identification string; K_S is S's public host key; I_C is C's
 * SSH_MSG_KEXINIT message and I_S is S's SSH_MSG_KEXINIT message that have been
 * exchanged before this part begins.</p>
 *
 * <ol>
 *	<li>C generates a random number x (1 &lt; x &lt; q) and computes
 *		e = g^x mod p.  C sends e to S.</li>
 *
 *	<li>S generates a random number y (0 &lt; y &lt; q) and computes
 *		f = g^y mod p.  S receives e.  It computes K = e^y mod p,
 *		H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
 *		(these elements are encoded according to their types; see below), and
 *		signature s on H with its private host key.  S sends (K_S || f || s)
 *		to C.  The signing operation may involve a second hashing operation.</li>
 *
 *	<li>C verifies that K_S really is the host key for S (e.g., using
 *		certificates or a local database).  C is also allowed to accept the key
 *		without verification; however, doing so will render the protocol
 *		insecure against active attacks (but may be desirable for practical
 *		reasons in the short term in many environments).  C then computes
 *		K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K),
 *		and verifies the signature s on H.</li>
 * </ol>
 *
 * <p>Values of 'e' or 'f' that are not in the range [1, p-1] MUST NOT be sent
 * or accepted by either side.  If this condition is violated, the key exchange
 * fails.</p>
 *
 * <p>This is implemented with the following messages.  The hash algorithm for
 * computing the exchange hash is defined by the method name, and is called
 * HASH.  The public key algorithm for signing is negotiated with the
 * SSH_MSG_KEXINIT messages.</p>
 *
 * <p>First, the client sends the following:</p>
 * <pre>
 *		byte      SSH_MSG_KEXDH_INIT
 *		mpint     e
 * </pre>
 *
 * <p>The server then responds with the following:</p>
 * <pre>
 *		byte      SSH_MSG_KEXDH_REPLY
 *		string    server public host key and certificates (K_S)
 *		mpint     f
 *		string    signature of H
 * </pre>
 *
 * <p>The hash H is computed as the HASH hash of the concatenation of the
 * following:</p>
 * <pre>
 *		string    V_C, the client's identification string (CR and LF excluded)
 *		string    V_S, the server's identification string (CR and LF excluded)
 *		string    I_C, the payload of the client's SSH_MSG_KEXINIT
 *		string    I_S, the payload of the server's SSH_MSG_KEXINIT
 *		string    K_S, the host key
 *		mpint     e, exchange value sent by the client
 *		mpint     f, exchange value sent by the server
 *		mpint     K, the shared secret
 * </pre>
 *
 * <p>This value is called the exchange hash, and it is used to authenticate the
 * key exchange.  The exchange hash SHOULD be kept secret.</p>
 *
 * <p>The signature algorithm MUST be applied over H, not the original data.
 * Most signature algorithms include hashing and additional padding (e.g.,
 * "ssh-dss" specifies SHA-1 hashing).  In that case, the data is first hashed
 * with HASH to compute H, and H is then hashed with SHA-1 as part of the
 * signing operation.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-7">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Diffie-Hellman Key Exchange</a>
 * </p>
 *
 * <p><strong>Note:</strong> Instances should be created using the
 * {@code AlgorithmManager} factory.</p>
 *
 * @see org.vngx.jsch.algorithm.AlgorithmManager
 * 
 * @author Michael Laudati
 */
public interface DiffieHellman extends Algorithm {

	/**
	 * Sets the public (prime) number for D-H key exchange.
	 *
	 * @param p public (prime) exchange
	 */
	void setP(byte[] p);

	/**
	 * Sets the public base for D-H key exchange.
	 *
	 * @param g
	 */
	void setG(byte[] g);

	/**
	 * Returns 'e' the exchange value sent from client calculated by
	 * e = g^x mod p (and x is a random number (1 &lt; x &lt; (p-1)/2))/
	 *
	 * @return exchange value calculate by client
	 * @throws Exception if any errors occur
	 */
	byte[] getE() throws Exception;

	/**
	 * Sets 'f' the exchange value sent by the server after receiving 'e'
	 * calculated by f = g^y mod p (and y (0 &lt; y &lt; q).
	 *
	 * @param f exchange value from server
	 */
	void setF(byte[] f);

	/**
	 * Returns the shared secret key calculated by K = f^x mod p.
	 *
	 * @return shared secret key
	 * @throws Exception if any errors occur
	 */
	byte[] getK() throws Exception;
	
}
