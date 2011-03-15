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

package org.vngx.jsch;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Enum constants to represent the available <code>Channel</code> types.
 * Provides static method for converting SSH standardized channel names to
 * supported channel types.
 *
 * @see org.vngx.jsch.Channel
 *
 * @author Michael Laudati
 */
public enum ChannelType {

	/** Channel constant for ChannelSession. */
	SESSION("session"),
	/** Channel constant for ChannelShell. */
	SHELL("shell"),
	/** Channel constant for ChannelExec. */
	EXEC("exec"),
	/** Channel constant for ChannelX11. */
	X11("x11"),											// Requested, not opened directly
	/** Channel constant for ChannelAgentForwarding. */
	AGENT_FORWARDING("auth-agent@openssh.com"),			// Requested, not opened directly
	/** Channel constant for ChannelDirectTCPIP. */
	DIRECT_TCP_IP("direct-tcpip"),
	/** Channel constant for ChannelForwardedTCPIP. */
	FORWARDED_TCP_IP("forwarded-tcpip"),				// Requested, not opened directly
	/** Channel constant for ChannelSFTP. */
	SFTP("sftp"),
	/** Channel constant for ChannelSubsystem. */
	SUBSYSTEM("subsystem");

	/** Official SSH channel type name. */
	final String _typeName;


	/**
	 * Creates a new enum <code>ChannelType</code> for the specified type name.
	 *
	 * @param name of channel type
	 */
	private ChannelType(String typeName) {
		if( typeName == null || typeName.length() == 0 ) {
			throw new IllegalArgumentException("Channel type name cannot be null/empty: "+typeName);
		}
		_typeName = typeName;
	}
	
	/**
	 * Creates a new instance of <code>Channel</code> for this type. Method
	 * should remain default access as instances should only be created
	 * by <code>Session</code> instances.
	 *
	 * @return new instance of channel of this type
	 */
	Channel createChannel(Session session) {
		switch( this ) {
			case SESSION:			return new ChannelSession(session);
			case SHELL:				return new ChannelShell(session);
			case EXEC:				return new ChannelExec(session);
			case X11:				return new ChannelX11(session);
			case AGENT_FORWARDING:	return new ChannelAgentForwarding(session);
			case DIRECT_TCP_IP:		return new ChannelDirectTCPIP(session);
			case FORWARDED_TCP_IP:	return new ChannelForwardedTCPIP(session);
			case SFTP:				return new ChannelSftp(session);
			case SUBSYSTEM:			return new ChannelSubsystem(session);
			default: throw new UnsupportedOperationException(_typeName+" channel type is not supported");
		}
	}

	/**
	 * Returns the standard SSH type name for the channel.
	 *
	 * @return type name
	 */
	public String getTypeName() {
		return _typeName;
	}

	/**
	 * Returns the <code>ChannelType</code> for the specified SSH channel name.
	 *
	 * @param type name
	 * @return ChannelType
	 */
	public static ChannelType getChannelType(String type) {
		return type != null ? CHANNELS.get(type.toLowerCase()) : null;
	}

	/**
	 * Returns true if the channel name matches this channel type's name.
	 *
	 * @param channelName to check
	 * @return true if channel name matches this channel type
	 */
	boolean equals(String channelName) {
		return _typeName.equals(channelName);
	}

	/** Map of ChannelTypes stored by their standard SSH type names. */
	private final static Map<String,ChannelType> CHANNELS;
	/** Static initialization of channel type map. */
	static {
		Map<String,ChannelType> channels = new HashMap<String,ChannelType>();
		for( ChannelType type : ChannelType.values() ) {
			channels.put(type.getTypeName(), type);
		}
		CHANNELS = Collections.unmodifiableMap(channels);
	}
	
}
