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
import java.util.Arrays;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.JSch;
import org.vngx.jsch.Session;
import org.vngx.jsch.algorithm.UnsupportedAlgorithmException;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.Logger;

/**
 * <p>Base implementation of {@code KexAlgorithm} for performing the two
 * standard Diffie Hellman based key exchange as described in RFC 4253.  Two
 * REQUIRED key exchange methods have been defined:
 * <pre>
 *	diffie-hellman-group1-sha1 REQUIRED
 *	diffie-hellman-group14-sha1 REQUIRED
 * </pre>
 * </p>
 *
 * <p>Both methods use the same algorithm/packets, just a different Oakley
 * group.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-8">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Diffie-Hellman Key Exchange</a>
 * </p>
 *
 * @see org.vngx.jsch.kex.DiffieHellman
 * @see org.vngx.jsch.kex.KexAlgorithm
 *
 * @author Michael Laudati
 */
public abstract class DHGroupKexAlgorithm extends AbstractDHKexAlgorithm {

	/** Constant value 'g' is a generator for a subgroup of GF(p). */
	private final byte[] _g;
	/** Constant value 'p' is a large safe prime number. */
	private final byte[] _p;
	/**
	 * Generated value from g^x mod p (x is a random number
	 * {@literal (1 < x < (p-1)/2)}). 
	 */
	private byte[] _e;


	/**
	 * Creates a new instance of {@code DHGroupKexAlgorithm} with the specified
	 * {@code g} and {@code p} values for performing the Diffie Hellman
	 * algorithm.
	 *
	 * @param g (generator)
	 * @param p (large safe prime)
	 * @throws UnsupportedAlgorithmException if any errors occur
	 */
	protected DHGroupKexAlgorithm(final byte[] g, final byte[] p) throws UnsupportedAlgorithmException {
		_g = g;
		_p = p;
	}

	@Override
	protected void init(Session session, byte[] I_C, byte[] I_S) throws JSchException, IOException {
		super.init(session, I_C, I_S);	// Initialize values

		// Generate value e <- g^x mod p  (x is a random number (1 < x < (p-1)/2))
		_dh.setG(_g);
		_dh.setP(_p);
		try {
			_e = _dh.getE();	// Calculate 'e' to send to server
		} catch(Exception e) {
			throw new KexException("Failed to generate 'e' with Diffie-Hellman", e);
		}

		// Send SSH packet to begin the diffie hellman exchange
		// byte  SSH_MSG_KEXDH_INIT(30)
		// mpint e <- g^x mod p  (x is a random number (1 < x < (p-1)/2))
		_packet.reset();
		_buffer.putByte(SSH_MSG_KEXDH_INIT);
		_buffer.putMPInt(_e);
		_session.write(_packet);
		_state = SSH_MSG_KEXDH_REPLY;
		JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_KEXDH_INIT sent, expecting SSH_MSG_KEXDH_REPLY");
	}

	@Override
	protected boolean next(final Buffer buffer) throws JSchException, IOException {
		switch( buffer.getCommand() & _state ) {	// Verify state of command
			case SSH_MSG_KEXDH_REPLY:
				// The server responds with:
				// byte      SSH_MSG_KEXDH_REPLY(31)
				// string    server public host key and certificates (K_S)
				// mpint     f (server secret)
				// string    signature of H
				buffer.setOffSet(6);

				K_S = buffer.getString();			// Read in public host key
				byte[] f = buffer.getMPInt();		// Read in 'f' server secret
				byte[] sigOfH = buffer.getString();	// Read in signature of H

				_dh.setF(f);			// Set server's secret 'f' in DH
				try {
					_K = _dh.getK();	// to generate shared key 'K'
				} catch(Exception e) {
					throw new KexException("Failed to generate shared secret 'k'", e);
				}

				// The exchange hash H is computed as the hash of the concatenation of:
				// string    V_C, the client's version string (CR and NL excluded)
				// string    V_S, the server's version string (CR and NL excluded)
				// string    I_C, the payload of the client's SSH_MSG_KEXINIT
				// string    I_S, the payload of the server's SSH_MSG_KEXINIT
				// string    K_S, the host key
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
				_buffer.putMPInt(_e);
				_buffer.putMPInt(f);
				_buffer.putMPInt(_K);
				_H = Arrays.copyOf(_buffer.getArray(), _buffer.getLength());
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
