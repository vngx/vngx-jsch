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

import java.io.IOException;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.Packet;
import org.vngx.jsch.Session;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.Algorithm;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.hash.Hash;
import org.vngx.jsch.util.KeyType;

/**
 * <p>Abstract class for defining key exchange algorithm implementations.  After
 * the SSH_MSG_KEXINIT message exchange, the key exchange algorithm is run.  It
 * may involve several packet exchanges, as specified by the key exchange
 * method.</p>
 *
 * <p>The key exchange produces two values: a shared secret K, and an exchange
 * hash H.  Encryption and authentication keys are derived from these.  The
 * exchange hash H from the first key exchange is additionally used as the
 * session identifier, which is a unique identifier for this connection.  It is
 * used by authentication methods as a part of the data that is signed as a
 * proof of possession of a private key.  Once computed, the session identifier
 * is not changed, even if keys are later re-exchanged.</p>
 *
 * <p>Each key exchange method specifies a hash function that is used in the key
 * exchange.  The same hash algorithm MUST be used in key derivation.  Here,
 * we'll call it HASH.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-7">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Key Exchange</a></p>
 *
 * @see org.vngx.jsch.kex.KeyExchange
 *
 * @author Michael Laudati
 */
public abstract class KexAlgorithm implements Algorithm {
	
	/** Constant state code for when key exchange is completed. */
	public final static int STATE_END = 0;

	/** Buffer for sending and receiving SSH packets. */
	protected final Buffer _buffer = new Buffer();
	/** SSH packet for sending and receiving requests to SSH server for kex. */
	protected final Packet _packet = new Packet(_buffer);
	/** Session the key exchange is for. */
	protected Session _session;
	/** Client version String sent to remote SSH server (CR and LF excluded). */
	protected byte[] V_C;
	/** Server version String read from SSH server response (CR and LF excluded). */
	protected byte[] V_S;
	/** Client's SSH_MSG_KEXINIT payload sent to server. */
	protected byte[] I_C;
	/** Server's SSH_MSG_KEXINIT payload received from server. */
	protected byte[] I_S;
	/** K_S is the server's public host key. */
	protected byte[] K_S;
	/** Host key type. */
	protected KeyType _hostKeyType;
	/** State code for current state of key exchange. */
	protected int _state = -1;

	/**
	 * {@code Hash} instance used to hash values in key exchange. This hash must
	 * be used in key derivation.
	 */
	protected final Hash _hash;
	/** 
	 * K is the shared secret created by both the server and the client used
	 * in key derivation.
	 */
	protected byte[] _K;
	/** 
	 * The exchange hash H used to derive the encryption and authentication 
	 * keys. The first kex exchange hash is also used as the session identifier.
	 */
	protected byte[] _H;


	/**
	 * Creates a new instance of {@code KexAlgorithm} which uses the specified
	 * {@code hash} implementation for key exchange.  Every kex algorithm must
	 * have a {@code Hash} which is used in key derivation for {@code Cipher}s
	 * and {@code MAC}s used in the transport layer for the session.
	 *
	 * @param hash implementation
	 * @throws IllegalArgumentException if hash is null
	 */
	protected KexAlgorithm(final Hash hash) {
		if( hash == null ) {
			throw new IllegalArgumentException("Hash cannot be null for kex algorithm");
		}
		_hash = hash;
	}

	/**
	 * Initializes the key exchange algorithm for the specified {@code session},
	 * {@code I_C} client kex init and {@code I_S} server kex init payloads.
	 * Implementations should override the {@code init} method and start the
	 * specific key exchange algorithm process with the appropriate SSH message
	 * code.
	 * 
	 * @param session instance
	 * @param I_C client's KEXINIT payload
	 * @param I_S server's KEXINIT payload
	 * @throws JSchException if any errors occur
	 * @throws IOException if any IO related errors occur
	 */
	protected void init(Session session, byte[] I_C, byte[] I_S) throws JSchException, IOException {
		_session = session;
		this.V_C = Util.str2byte(_session.getClientVersion());
		this.V_S = Util.str2byte(_session.getServerVersion());
		this.I_C = I_C;	// Consider making a safe copy of the client's and
		this.I_S = I_S;	// server's kex init payloers
	}

	/**
	 * Processes the next key exchange response from the server.
	 *
	 * @param buffer containing server response
	 * @return true if response processed successfully
	 * @throws JSchException if any errors occur
	 * @throws IOException if any IO errors occur
	 */
	protected abstract boolean next(final Buffer buffer) throws JSchException, IOException;

	/**
	 * Returns the current state of the key exchange.  Since the key exchange
	 * may take several requests back and forth between server and client, the
	 * state helps to track the process and ensure both sides are in the same
	 * state.
	 *
	 * @return state of key exchange process
	 */
	protected int getState() {
		return _state;
	}

	/**
	 * Returns the {@code Hash} instance used for the key exchange and key
	 * derivation for encryption.
	 *
	 * @return hash used for key exchange
	 */
	public Hash getHash() {
		return _hash;
	}

	/**
	 * Returns the exchange hash H generated in the key exchange.  The exchange
	 * hash H is a sensitive piece of data and should be carefully protected and
	 * cleared after use.
	 *
	 * @return exchange hash H
	 */
	public byte[] getH() {
		return _H;
	}

	/**
	 * Returns the shared secret key K generated during the key exchange.  The
	 * shared secret is a sensitive piece of data and should be carefully
	 * protected and cleared after use.
	 *
	 * @return shared secret K
	 */
	public byte[] getK() {
		return _K;
	}

}
