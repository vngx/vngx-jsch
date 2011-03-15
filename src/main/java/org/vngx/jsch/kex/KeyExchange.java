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

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import org.vngx.jsch.Buffer;
import org.vngx.jsch.JSch;
import org.vngx.jsch.Packet;
import org.vngx.jsch.algorithm.Random;
import org.vngx.jsch.Session;
import org.vngx.jsch.UserInfo;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.AlgorithmManager;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.cipher.Cipher;
import org.vngx.jsch.config.SessionConfig;
import org.vngx.jsch.constants.MessageConstants;
import org.vngx.jsch.constants.SSHConstants;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.HostKey;
import org.vngx.jsch.util.HostKeyRepository;
import org.vngx.jsch.util.HostKeyRepository.Check;
import org.vngx.jsch.util.Logger;
import org.vngx.jsch.util.Logger.Level;

/**
 * <p>Key Exchange is any method in cryptography by which cryptographic keys are
 * exchanged between users, allowing use of a cryptographic algorithm. If Alice
 * and Bob wish to exchange encrypted messages, each must be equipped to decrypt
 * received messages and to encrypt sent messages. The nature of the information
 * they require to do so depends on the encryption technique they might use. If
 * they use a code, both will require a copy of the same codebook. If they use a
 * cipher, they will need appropriate keys. If the cipher is a symmetric key
 * cipher, both will need a copy of the same key. If an asymmetric key cipher
 * with the public/private key property, both will need the other's public 
 * key.</p>
 *
 * <p>Of course, if the DH private parameters for the client and server are
 * revealed, then the session key is revealed, but these items can be thrown
 * away after the key exchange completes.  It's worth pointing out that these
 * items should not be allowed to end up on swap space and that they should be
 * erased from memory as soon as the key exchange completes.</p>
 *
 * <p><a href="http://tools.ietf.org/html/rfc4253#section-7">RFC 4253 - The
 * Secure Shell (SSH) Transport Layer Protocol: Key Exchange</a></p>
 *
 * @see org.vngx.jsch.kex.KexAlgorithm
 * @see org.vngx.jsch.kex.KexProposal
 * 
 * @author Michael Laudati
 */
public final class KeyExchange {

	/** Number of bytes in the KEX_INIT 'cookie'. */
	final static int KEX_COOKIE_LENGTH = 16;

	/** Session the key exchange belongs to. */
	final Session _session;
	/** Buffer for sending SSH packets. */
	final Buffer _buffer = new Buffer();
	/** True if session is currently in process of a key exchange. */
	final AtomicBoolean _inKeyExchange = new AtomicBoolean(false);

	/** Guessed algorithms during key exchange. */
	KexProposal _proposal;
	/** Key exchange algorithm which performs the actual exchange. */
	KexAlgorithm _kexAlg;
	/** Client's SSH_MSG_KEXINIT payload sent to server. */
	byte[] I_C;
	/** Server's SSH_MSG_KEXINIT payload received from server. */
	byte[] I_S;
	/** Host key generated after key exchange and validation. */
	HostKey _hostKey;
	

	/**
	 * Creates a new instance of {@code KeyExchange} for the specified
	 * {@code session} instance.  A key exchange should not be created
	 * until after the session has established a socket connection to the remote
	 * host and exchanged version information.
	 *
	 * @param session to create key exchange for
	 */
	public KeyExchange(Session session) {
		if( session == null ) {
			throw new IllegalArgumentException("Session cannot be null");
		}
		_session = session;
	}

	public byte[] runFirstKex() throws Exception {
		// Initialize the key exchange for session and check expected response
		sendKexInit();
		if( _session.read(_buffer).getCommand() != SSH_MSG_KEXINIT ) {
			throw new KexException("Invalid kex protocol, expected SSH_MSG_KEXINIT(20): " + _buffer.getCommand());
		}
		JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_KEXINIT received");

		// Read server response and generate appropriate kex algorithm
		receiveKexInit(_buffer);

		// Check host key against known hosts before continuing...
		checkHost(_kexAlg);

		// Request new set of keys after initial key exchange
		sendNewKeys();
		// Read SSH_MSG_NEWKEYS response from server
		if( _session.read(_buffer).getCommand() != SSH_MSG_NEWKEYS ) {
			throw new KexException("Invalid kex protocol, expected SSH_MSG_NEWKEYS(21): " + _buffer.getCommand());
		}
		JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_NEWKEYS received");

		// Return the session ID (copy of exchange hash H) from first kex
		return Arrays.copyOf(_kexAlg.getH(), _kexAlg.getH().length);
	}

	public void rekey(Buffer rekeyBuffer) throws Exception {
		receiveKexInit(rekeyBuffer);
	}

	/**
	 * Returns true if in the process of a key exchange.
	 *
	 * @return true if in process of a key exchange
	 */
	public boolean inKex() {
		return _inKeyExchange.get();
	}

	public void kexCompleted() {
		_inKeyExchange.set(false);
	}
	
	/**
	 * <p>Sends a key exchange init request message to the server using a local
	 * packet specifying the client's proposals for key exchange.</p>
	 *
	 * <p><a href="http://tools.ietf.org/html/rfc4253#section-7.1">RFC 4253 -
	 * 7.1. Algorithm Negotiation</a></p>
	 *
	 * @throws KexException if any errors occur
	 */
	public void sendKexInit() throws KexException {
		// Check if already in middle of a kex
		if( _inKeyExchange.getAndSet(true) ) {	// Flip state flag entering kex
			return;	// Return if already in process of kex
		}
		Buffer kexBuffer = new Buffer();			// Use a separate packet and buffer since
		Packet kexPacket = new Packet(kexBuffer);	// kex may be invoked by user thread
		try {
			// Random instance for generating the kex cookie.  The 'cookie' MUST
			// be a random value generated by the sender. Its purpose is to make
			// it impossible for either side to fully determine the keys and the
			// session identifier.
			final Random random = AlgorithmManager.getManager().createAlgorithm(Algorithms.RANDOM, _session);

			// Construct the KEX INIT message packet
			// byte		SSH_MSG_KEXINIT(20)
			// byte[16]	cookie (random bytes)
			// string	kex_algorithms
			// string	server_host_key_algorithms
			// string	encryption_algorithms_client_to_server
			// string	encryption_algorithms_server_to_client
			// string	mac_algorithms_client_to_server
			// string	mac_algorithms_server_to_client
			// string	compression_algorithms_client_to_server
			// string	compression_algorithms_server_to_client
			// string	languages_client_to_server
			// string	languages_server_to_client
			// byte		boolean first_kex_packet_follows
			// uint32	0 (reserved for future extension)
			kexPacket.reset();
			kexBuffer.putByte(SSH_MSG_KEXINIT);
			random.fill(kexBuffer.getArray(), kexBuffer.getIndex(), KEX_COOKIE_LENGTH);
			kexBuffer.skip(KEX_COOKIE_LENGTH);	// Move index forward
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_ALGORITHMS));
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_SERVER_HOST_KEY));
			kexBuffer.putString(_session.getConfig().getCiphersC2S());	// Checked list of client-to-server ciphers
			kexBuffer.putString(_session.getConfig().getCiphersS2C());	// Checked list of server-to-client ciphers
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_MAC_C2S));
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_MAC_S2C));
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_COMPRESSION_C2S));
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_COMPRESSION_S2C));
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_LANG_C2S));
			kexBuffer.putString(_session.getConfig().getString(SessionConfig.KEX_LANG_S2C));
			kexBuffer.putByte((byte) 0);	// 0 is false, not sending guessed packet
			kexBuffer.putInt(0);

			// Set the client's kex algorithm initialization message
			I_C = Arrays.copyOfRange(kexBuffer.getArray(), 5, kexBuffer.getIndex());
			_session.write(kexPacket);	// Send key exchange init message to server
			JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_KEXINIT sent");
		} catch(Exception e) {
			throw new KexException("Failed to send SSH_MSG_KEXINIT", e);
		} finally {
			kexBuffer.clear();	// Clear buffer to ensure sensitive data is wiped
		}
	}

	/**
	 * <p>Receives the server's key exchange KEXINIT from the specified
	 * {@code buffer}.</p>
	 *
	 * @param buffer containing server's SSH_MSG_KEXINIT message
	 * @throws KexException if any errors occur
	 */
	private void receiveKexInit(final Buffer buffer) throws KexException {
		// Read the server's proposal for kex algorithms from buffer
		// Check packet length for compression and set size of data portion
		int packetLength = buffer.getInt();
		if( packetLength != buffer.getLength() ) {
			buffer.getByte(); /* padding length*/	
			// Compressed: (uncompressed data length) - (packet length int + padding length byte)
			I_S = new byte[buffer.getIndex() - 5];
		} else {
			// Not compressed: (packet length) - (padding length byte )- (padding length)
			I_S = new byte[packetLength - 1 - buffer.getByte()];
		}
		buffer.getBytes(I_S);	// Read in server proposal from buffer

		// If rekeying was activated by server, then send client's proposal for kex
		if( !_inKeyExchange.get() ) {
			sendKexInit();
		}

		// Guess algorithms to use from the client's and server's proposals
		_proposal = KexProposal.createProposal(I_S, I_C);
		if( JSch.getLogger().isEnabled(Logger.Level.DEBUG) ) {
			JSch.getLogger().log(Level.DEBUG, _proposal.toString());
		}

		// If not authorized yet, don't allow 'none' cipher to be used, throw
		// an exception to prevent auth data from being sent in the clear
		if( !_session.isAuthenticated() &&
				( Cipher.CIPHER_NONE.equals(_proposal.getCipherAlgCtoS()) ||
				  Cipher.CIPHER_NONE.equals(_proposal.getCipherAlgStoC()) ) ) {
			throw new KexException("Cipher 'none' cannot be used before authentication has succeeded");
		}

		// Attempt to create kex algorithm to perform kex
		try {
			JSch.getLogger().log(Logger.Level.INFO, "Kex method: " + _proposal.getKexAlg());
			_kexAlg = AlgorithmManager.getManager().createAlgorithm(_proposal.getKexAlg(), _session);
			_kexAlg.init(_session, I_C, I_S);	// Initialize and return
		} catch(Exception e) {
			throw new KexException("Failed to load KexAlgorithm '"+_proposal.getKexAlg()+"'", e);
		}

		try {
			do {
				if( !_kexAlg.next(_session.read(_buffer)) ) {
					throw new KexException("Kex failure, host key could not be verified");
				}
			} while( _kexAlg.getState() != KexAlgorithm.STATE_END );	// Do until kex is completed
		} catch(KexException ke) {
			throw ke;
		} catch(Exception e) {
			throw new KexException("Failed to run KexAlgorithm", e);
		}
	}

	/**
	 * <p>Sends message to server to end key exchange and start using new keys.
	 * Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.  This
	 * message is sent with the old keys and algorithms.  All messages sent
	 * after this message MUST use the new keys and algorithms. When this
	 * message is received, the new keys and algorithms MUST be used for
	 * receiving.</p>
	 *
	 * <p>The purpose of this message is to ensure that a party is able to
	 * respond with an SSH_MSG_DISCONNECT message that the other party can
	 * understand if something goes wrong with the key exchange.</p>
	 *
	 * <p><a href="http://tools.ietf.org/html/rfc4253#section-7.3">RFC 4253 -
	 * 7.3. Taking Keys Into Use</a></p>
	 *
	 * @throws KexException if any errors occur
	 */
	public void sendNewKeys() throws KexException {
		try {
			// Send SSH_MSG_NEWKEYS request to server
			Buffer buffer = new Buffer(500);
			Packet packet = new Packet(buffer);
			packet.reset();
			buffer.putByte(SSH_MSG_NEWKEYS);
			_session.write(packet);
			JSch.getLogger().log(Logger.Level.INFO, "SSH_MSG_NEWKEYS sent");
		} catch(Exception e) {
			throw new KexException("Failed to send SSH_MSG_NEWKEYS request", e);
		}
	}

	/**
	 * Checks if the host received during key exchange is a valid host as
	 * determined by the user and known hosts.
	 *
	 * @param kex instance
	 * @throws JSchException if any errors occur
	 */
	private void checkHost(KexAlgorithm kex) throws JSchException {
		UserInfo _userinfo = _session.getUserInfo();

		// Check if host key alias exists and use it, or if it's not present and
		// not using default port, set the port in host to check
		String chost = _session.getHost();
		if( _session.getHostKeyAlias() != null ) {
			chost = _session.getHostKeyAlias();
		} else if( _session.getPort() != SSHConstants.DEFAULT_SSH_PORT ) {
			chost = "[" + chost + "]:" + _session.getPort();
		}

		// Check host against known hosts repository
		HostKeyRepository hkr = JSch.getInstance().getHostKeyRepository();
		Check keyCheck;
		synchronized( hkr ) {
			keyCheck = hkr.check(chost, kex.K_S);
		}

		boolean insert = false;
		String shkc = _session.getConfig().getString(SessionConfig.STRICT_HOST_KEY_CHECKING);
		if( ("ask".equals(shkc) || "yes".equals(shkc)) && keyCheck == Check.CHANGED ) {
			String file = hkr.getKnownHostsRepositoryID() != null ?
				hkr.getKnownHostsRepositoryID() : SSHConstants.KNOWN_HOSTS;

			// Notify user host key changed (ask if requested) and throw exception
			// if user doesn't accept the new key
			if( _userinfo != null ) {
				if( "ask".equals(shkc) ) {
					if( !_userinfo.promptYesNo(String.format(MessageConstants.PROMPT_REPLACE_KEY,
							kex._hostKeyType.DISPLAY_NAME, Util.getFingerPrint(kex.K_S), file)) ) {
						throw new JSchException("HostKey has changed (StrictHostKeyChecking:ask): "+chost);
					}
				} else {  // shkc.equals("yes")
					_userinfo.showMessage(String.format(MessageConstants.INVALID_SERVER_HOST,
							kex._hostKeyType.DISPLAY_NAME, Util.getFingerPrint(kex.K_S), file));
					throw new JSchException("HostKey has changed (StrictHostKeyChecking:yes): "+chost);
				}
			}

			// Remove the old key from the repository
			synchronized ( hkr ) {
				hkr.remove(chost, kex._hostKeyType, null);
				insert = true;
			}
		}

		if( ("ask".equals(shkc) || "yes".equals(shkc)) && keyCheck != Check.OK && !insert ) {
			if( "yes".equals(shkc) ) {
				throw new JSchException("HostKey does not match known hosts (StrictHostKeyChecking:yes): "+chost);
			}
			if( _userinfo != null ) {
				if( !_userinfo.promptYesNo(String.format(MessageConstants.PROMPT_UNKNOWN_KEY,
						chost, kex._hostKeyType.DISPLAY_NAME, Util.getFingerPrint(kex.K_S))) ) {
					throw new JSchException("HostKey does not match known hosts (StrictHostKeyChecking:ask): "+chost);
				}
				insert = true;
			} else {
				if( keyCheck == Check.NOT_INCLUDED ) {
					throw new JSchException("UnknownHostKey: "+chost+". "+kex._hostKeyType+" key fingerprint is "+Util.getFingerPrint(kex.K_S));
				} else {
					throw new JSchException("HostKey has been changed (StrictHostKeyChecking:ask): " + chost);
				}
			}
		}

		if( "no".equals(shkc) && keyCheck == Check.NOT_INCLUDED ) {
			insert = true;
		}
		if( keyCheck == Check.OK && JSch.getLogger().isEnabled(Logger.Level.INFO) ) {
			JSch.getLogger().log(Logger.Level.INFO, "Host '"+chost+"' is known and matches the "+kex._hostKeyType+" host key");
		}
		if( insert && JSch.getLogger().isEnabled(Logger.Level.WARN) ) {
			JSch.getLogger().log(Logger.Level.WARN, "Permanently added '"+chost+"' ("+kex._hostKeyType+") to the list of known hosts.");
		}

		// Create host key instance
		_hostKey = HostKey.createHostKey(chost, kex.K_S, _session.getConfig().getBoolean(SessionConfig.HASH_KNOWN_HOSTS));
		if( insert ) {
			synchronized( hkr ) {
				hkr.add(_hostKey, _userinfo);
			}
		}
	}

	/**
	 * Returns the key exchange proposals agreed upon during the key exchange.
	 *
	 * @return key exchange proposals
	 */
	public KexProposal getKexProposal() {
		return _proposal;
	}

	public KexAlgorithm getKexAlgorithm() {
		return _kexAlg;
	}

}
