/*
 * Copyright (c) 2002-2010 Atsuhiko Yamanaka, JCraft,Inc.  All rights reserved.
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
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
 * INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.vngx.jsch;

import static org.vngx.jsch.constants.ConnectionProtocol.*;

import org.vngx.jsch.constants.MessageConstants;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.userauth.IdentityManager;
import org.vngx.jsch.userauth.Identity;
import org.vngx.jsch.util.Logger.Level;
import java.io.IOException;
import java.util.Arrays;
import java.util.Set;

/**
 * Implementation of <code>Channel</code> for agent forwarding. Agent forwarding
 * allows a chain of SSH connections to forward key challenges back to the
 * original agent, obviating the need for passwords or private keys on any
 * intermediate machines.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
final class ChannelAgentForwarding extends Channel {

	/** Local maximum window size. */
	private static final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	/** Local maximum packet size. */
	private static final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

	/** Constant code for client agent to request identities. */
	private static final byte SSH2_AGENTC_REQUEST_IDENTITIES	= 11;
	/** Constant code for agent to answer identities. */
	private static final byte SSH2_AGENT_IDENTITIES_ANSWER		= 12;
	/** Constant code for client agent to sign the request. */
	private static final byte SSH2_AGENTC_SIGN_REQUEST			= 13;
	/** Constant code for agent to sign the response. */
	private static final byte SSH2_AGENT_SIGN_RESPONSE			= 14;
	/** Constant code for client agent to add an identity (unsupported). */
	@SuppressWarnings("unused")
	private static final byte SSH2_AGENTC_ADD_IDENTITY			= 17;
	/** Constant code for client agent to remove an identity (unsupported). */
	@SuppressWarnings("unused")
	private static final byte SSH2_AGENTC_REMOVE_IDENTITY		= 18;
	/** Constant code for client agent to remove all identities (unsupported). */
	@SuppressWarnings("unused")
	private static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
	/** Constant code for agent failure. */
	private static final byte SSH2_AGENT_FAILURE				= 30;

	/** Read buffer for storing read data. */
	private final Buffer _readBuffer = new Buffer();	// TODO Specify sizes for buffers?
	/** Message buffer for sending message to server. */
	private final Buffer _messageBuffer = new Buffer();
	/** Write buffer for storing write data. */
	private final Buffer _writeBuffer = new Buffer();
	/** Packet for sending data over channel. */
	private final Packet _packet = new Packet(_writeBuffer);


	/**
	 * Creates a new instance of <code>ChannelAgentForwarding</code>.
	 *
	 * @param session
	 */
	ChannelAgentForwarding(Session session) {
		super(session, ChannelType.AGENT_FORWARDING);
		setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
		_connected = true;
	}

	@Override
	public void run() {
		try {
			sendOpenConfirmation();
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.DEBUG, "Failed to send channel open confirmation", e);
			_closed = true;
			disconnect();
		}
	}

	@Override
	void write(byte[] buffer, int offset, int length) throws IOException {
		_readBuffer.shift();
		if( _readBuffer.buffer.length < _readBuffer.index + length ) {
			byte[] newbuf = new byte[_readBuffer.getOffSet() + length];
			System.arraycopy(_readBuffer.buffer, 0, newbuf, 0, _readBuffer.buffer.length);
			_readBuffer.buffer = newbuf;
		}
		_readBuffer.putBytes(buffer, offset, length);

		int mlen = _readBuffer.getInt();
		if( mlen > _readBuffer.getLength() ) {
			_readBuffer.setOffSet(_readBuffer.getOffSet() - 4);
			return;
		}

		int typ = _readBuffer.getByte();

		Set<Identity> identities = IdentityManager.getManager().getIdentities();
		UserInfo userinfo = _session.getUserInfo();

		if( typ == SSH2_AGENTC_REQUEST_IDENTITIES ) {
			_messageBuffer.reset();
			_messageBuffer.putByte(SSH2_AGENT_IDENTITIES_ANSWER);
			synchronized ( identities ) {
				int count = 0;
				for( Identity identity : identities ) {
					if( identity.getPublicKeyBlob() != null ) {
						count++;
					}
				}
				_messageBuffer.putInt(count);
				for( Identity identity : identities ) {
					byte[] pubkeyblob = identity.getPublicKeyBlob();
					if( pubkeyblob != null ) {
						_messageBuffer.putString(pubkeyblob);
						_messageBuffer.putString("");
					}
				}
			}
			send(_messageBuffer.buffer, _messageBuffer.getOffSet(), _messageBuffer.getLength());
		} else if( typ == SSH2_AGENTC_SIGN_REQUEST ) {
			byte[] blob = _readBuffer.getString();
			byte[] data = _readBuffer.getString();
			int flags = _readBuffer.getInt();

			Identity identity = null;
			synchronized ( identities ) {
				for( Identity _identity : identities ) {
					if( _identity.getPublicKeyBlob() == null ) {
						continue;
					}
					if( !Arrays.equals(blob, _identity.getPublicKeyBlob()) ) {
						continue;
					}
					if( _identity.isEncrypted() ) {
						if( userinfo == null ) {
							continue;
						}
						while( _identity.isEncrypted() ) {
							if( !userinfo.promptPassphrase(String.format(MessageConstants.PROMPT_PASSPHRASE, _identity.getName())) ) {
								break;
							}
							String _passphrase = userinfo.getPassphrase();
							if( _passphrase == null ) {
								break;
							}

							byte[] passphrase = Util.str2byte(_passphrase);
							try {
								if( _identity.setPassphrase(passphrase) ) {
									break;
								}
							} catch(JSchException e) {
								break;
							}
						}
					}

					if( !_identity.isEncrypted() ) {
						identity = _identity;
						break;
					}
				}
			}

			byte[] signature = null;
			if( identity != null ) {
				signature = identity.getSignature(data);
			}

			_messageBuffer.reset();
			if( signature == null ) {
				_messageBuffer.putByte(SSH2_AGENT_FAILURE);
			} else {
				_messageBuffer.putByte(SSH2_AGENT_SIGN_RESPONSE);
				_messageBuffer.putString(signature);
			}
			send(_messageBuffer.buffer, _messageBuffer.getOffSet(), _messageBuffer.getLength());
		}
	}

	/**
	 * Sends the specified data as channel data through the session.
	 *
	 * @param buffer data to send
	 * @param offset in data
	 * @param length of data to send
	 * @throws IOException if any errors occur
	 */
	private void send(byte[] buffer, int offset, int length) throws IOException {
		_packet.reset();
		_writeBuffer.putByte(SSH_MSG_CHANNEL_DATA);
		_writeBuffer.putInt(_recipient);
		_writeBuffer.putInt(4 + length);
		_writeBuffer.putString(buffer, offset, length);
		try {
			_session.write(_packet, this, 4 + length);
		} catch(Exception e) {
			throw new IOException("Failed to send ChannelAgentForwarding data", e);
		}
	}

}
