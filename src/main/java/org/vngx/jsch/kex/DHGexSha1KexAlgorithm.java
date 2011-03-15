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

import static org.vngx.jsch.constants.TransportLayerProtocol.*;

import java.io.IOException;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.JSch;
import org.vngx.jsch.Session;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.util.Logger;

/**
 * Implementation of {@code KexAlgorithm} for
 * "diffie-hellman-group-exchange-sha1" key exchange for SSH.
 *
 * The "diffie-hellman-group-exchange-sha1" method specifies Diffie-Hellman
 * Group and Key Exchange with SHA-1 [FIPS-180-2] as HASH.
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
 * @author Michael Laudati
 */
public class DHGexSha1KexAlgorithm extends AbstractDHKexAlgorithm {

	// TODO Consider making min, preferred and max configurable values
	/** Constant for minimal size in bits of an acceptable group. */
	static final int MIN_GROUP_BITS = 1024;
	/** Constant for preferred size in bits of the group the server will send. */
	static final int PREFERRED_GROUP_BITS = 1024;
	/** Constant for maximal size in bits of an acceptable group. */
	static final int MAX_GROUP_BITS = 1024;

	/** Safe prime 'p' from server. */
	private byte[] _p;
	/** Generator for subgroup in GF (p) from server. */
	private byte[] _g;
	/** Generated value from g^x mod p (x is a random number (1 &lt; x &lt; (p-1)/2)). */
	private byte[] _e;


	
	public DHGexSha1KexAlgorithm() throws JSchException { }

	DHGexSha1KexAlgorithm(Hash hash) throws JSchException {
		super(hash);
	}

	@Override
	protected void init(Session session, byte[] I_C, byte[] I_S) throws JSchException, IOException {
		super.init(session, I_C, I_S);

		// Send SSH request for group exchange
		// byte    SSH_MSG_KEY_DH_GEX_REQUEST
		// uint32  min, minimal size in bits of an acceptable group
		// uint32  n, preferred size in bits of the group the server will send
		// uint32  max, maximal size in bits of an acceptable group
		_packet.reset();
		_buffer.putByte(SSH_MSG_KEX_DH_GEX_REQUEST);
		_buffer.putInt(MIN_GROUP_BITS);
		_buffer.putInt(PREFERRED_GROUP_BITS);
		_buffer.putInt(MAX_GROUP_BITS);
		_session.write(_packet);
		_state = SSH_MSG_KEX_DH_GEX_GROUP;
		JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_KEX_DH_GEX_REQUEST(" + MIN_GROUP_BITS + "<" + PREFERRED_GROUP_BITS +
				"<" + MAX_GROUP_BITS + ") sent, expecting SSH_MSG_KEX_DH_GEX_GROUP(31)");
	}

	@Override
	protected boolean next(Buffer buffer) throws JSchException, IOException {
		switch( buffer.getCommand() & _state ) {
			case SSH_MSG_KEX_DH_GEX_GROUP:
				// Server responds with
				// byte  SSH_MSG_KEX_DH_GEX_GROUP(31)
				// mpint p, safe prime
				// mpint g, generator for subgroup in GF (p)
				buffer.setOffSet(6);	// Advance to data

				// Generate value e <- g^x mod p  (x is a random number (1 < x < (p-1)/2))
				_dh.setP(_p = buffer.getMPInt());	// Read safe prime from server
				_dh.setG(_g = buffer.getMPInt());	// Read generator from server
				try {
					_e = _dh.getE();
				} catch(Exception e) {
					throw new KexException("Failed to generate 'e' with Diffie-Hellman", e);
				}

				// The client responds with:
				// byte  SSH_MSG_KEX_DH_GEX_INIT(32)
				// mpint e <- g^x mod p  (x is a random number (1 < x < (p-1)/2))
				_packet.reset();
				_buffer.putByte(SSH_MSG_KEX_DH_GEX_INIT);
				_buffer.putMPInt(_e);
				_session.write(_packet);
				_state = SSH_MSG_KEX_DH_GEX_REPLY;	// Update state for next call
				JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_KEX_DH_GEX_INIT(32) sent, expecting SSH_MSG_KEX_DH_GEX_REPLY(33)");
				return true;

			case SSH_MSG_KEX_DH_GEX_REPLY:
				// The server responds with:
				// byte      SSH_MSG_KEX_DH_GEX_REPLY(33)
				// string    server public host key blob (K_S)
				// mpint     f (server's secret)
				// string    signature of H (to verify host)
				buffer.setOffSet(6);	// Advance to data

				K_S = buffer.getString();			// Read in server key blob
				byte[] f = buffer.getMPInt();		// Read in 'f' server's secret
				byte[] sigOfH = buffer.getString();	// Read in signature of H

				_dh.setF(f);			// Set server's secret 'f' in DH
				try {
					_K = _dh.getK();	// to generate shared key 'K'
				} catch(Exception e) {
					throw new KexException("Failed to generate shared secret 'k'", e);
				}

				// The hash H is computed as the hash of the concatenation of:
				// string    V_C, the client's version string (CR and NL excluded)
				// string    V_S, the server's version string (CR and NL excluded)
				// string    I_C, the payload of the client's SSH_MSG_KEXINIT
				// string    I_S, the payload of the server's SSH_MSG_KEXINIT
				// string    K_S, the host key
				// uint32    min, minimal size in bits of an acceptable group
				// uint32    n, preferred size in bits of the group the server should send
				// uint32    max, maximal size in bits of an acceptable group
				// mpint     p, safe prime
				// mpint     g, generator for subgroup
				// mpint     e, exchange value sent by the client
				// mpint     f, exchange value sent by the server
				// mpint     K, the shared secret
				// This value is called the exchange hash, and it is used to
				// authenticate the key exchange
				_buffer.reset();
				_buffer.putString(V_C);
				_buffer.putString(V_S);
				_buffer.putString(I_C);
				_buffer.putString(I_S);
				_buffer.putString(K_S);
				_buffer.putInt(MIN_GROUP_BITS);
				_buffer.putInt(PREFERRED_GROUP_BITS);
				_buffer.putInt(MAX_GROUP_BITS);
				_buffer.putMPInt(_p);
				_buffer.putMPInt(_g);
				_buffer.putMPInt(_e);
				_buffer.putMPInt(f);
				_buffer.putMPInt(_K);
				_H = new byte[_buffer.getLength()];
				_buffer.reset();
				_buffer.getBytes(_H);
				_hash.update(_H, 0, _H.length);
				_H = _hash.digest(); // Generate hash from concatenated values

				boolean verifiedHost = verifyHostKey(sigOfH);
				JSch.getLogger().log(Logger.Level.INFO, "Host key "+_hostKeyType+" signature verified: " + verifiedHost);
				_state = STATE_END;
				return verifiedHost;

			default:
				throw new KexException("Invalid kex protocol, unexpected SSH command: " + buffer.getCommand());
		}
	}

}
