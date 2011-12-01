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
import static org.vngx.jsch.constants.TransportLayerProtocol.*;

import org.vngx.jsch.config.SessionConfig;
import org.vngx.jsch.constants.SSHConstants;
import org.vngx.jsch.constants.UserAuthProtocol;
import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.kex.KeyExchange;
import org.vngx.jsch.proxy.Proxy;
import org.vngx.jsch.userauth.UserAuth;
import org.vngx.jsch.util.HostKey;
import org.vngx.jsch.util.Logger;
import org.vngx.jsch.util.SocketFactory;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import javax.net.ServerSocketFactory;

/**
 *
 * TODO Add support for setting a ThreadFactory instance for creating all sub
 * threads in session and its channels
 *
 * TODO Add a reset method which resets all the state variables after
 * disconnecting from the SSH server or when the connect method runs
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class Session implements Runnable {

	/** Constant for keep alive message sent to SSH server. */
	private static final byte[] KEEP_ALIVE_MSG = Util.str2byte("keepalive@vngx.org");

	/** Remote host to connect SSH session to. */
	private final String _host;
	/** Port of remote host to connect SSH session to. */
	private final int _port;
	/** Username for connecting to remote host. */
	private final String _username;
	/** Version exchange instance. */
	private final VersionExchange _versionExchange;

	/** Socket factory instance for creating sockets; null to use default. */
	private SocketFactory _socketFactory = SocketFactory.DEFAULT_SOCKET_FACTORY;
	/** Socket instance used to make remote connection to SSH server. */
	private Socket _socket;
	/** Proxy to pass SSH session through; null indicates no proxy. */
	private Proxy _proxy;
	/** Lock to synchronize access to proxy instance. */
	private final Object _proxyLock = new Object();
	/** Connection timeout in milliseconds to set on socket (zero or less indicates no timeout). */
	private int _timeout = 0;
	
	/** True if the socket is connected to the remote host. */
	private boolean _connected = false;
	/** True if the session user has been authenticated by host. */
	private boolean _authenticated = false;
	/** Reference to this session runnable instance while active. */
	private Runnable _thread;
	/** Thread which runs this as Runnable. TODO Rename or remove... */
	private Thread _connectThread;
	/** True if the session's thread (and children) should run as daemon. */
	private boolean _daemonThread = false;
	/** Thread factory used for creating child threads. */
	private ThreadFactory _threadFactory = Executors.defaultThreadFactory();

	/** Input/output helper instance for active session. */
	private IO _io;
	/** TODO ??? Input stream set in session to be used in channels (exec, shell, subsystem). */
	InputStream _in;
	/** TODO ??? Output stream set in session to be used in channels (exec, shell, subsystem). */
	OutputStream _out;
	/** Object to lock on when writing output to session. */
	private final Object _writeLock = new Object();
	/** User interface for interacting with user. */
	private UserInfo _userinfo;

	//=== Key Exchange State Variables ===
	/** Key exchange for performing kex and storing state. */
	private KeyExchange _keyExchange;
	/** Host key generated after key exchange and validation. */
	private HostKey _hostKey;
	/** Session ID created from hash of host key. */
	private byte[] _sessionId;

	//=== Connection Parameters ===
	/** Alias for host which can be used when checking a host key. */
	private String _hostKeyAlias;
	/** TODO ??? alias for timeout? sets the same timeout value on socket. */
	private int _serverAliveInterval = 0;
	/** TODO ??? max amount of times to send keep alive message? */
	private int _serverAliveCountMax = 1;

	/** True if X11 forwarding is enabled in session (set with RequestX11). */
	boolean _x11Forwarding = false;
	/** True if agent forwarding is enabled in session (set with RequestAgentForwarding). */
	boolean _agentForwarding = false;


	private SessionIO _sessionIO;

	/** Session's configuration instance (allows override of global properties). */
	private final SessionConfig _config;
	/**
	 * Maintains the state of a global request/reply, blocking additional global
	 * requests to ensure only one global request/reply is handled at a time. */
	private final GlobalRequestReply _globalRequest = new GlobalRequestReply();
	/** Map to store the session's channels by channel ID. */
	private final ConcurrentMap<Integer,Channel> _channels = new ConcurrentHashMap<Integer,Channel>();


	/**
	 * Creates a new instance of <code>Session</code>.  Sessions should only be
	 * created by the <code>JSch</code> singleton factory, hence the package
	 * access level for the constructor.
	 *
	 * @param host to connect to
	 * @param port to connect to
	 * @param username to connect with
	 */
	Session(String host, int port, String username) {
		this(host, port, username, null);
	}

	/**
	 * Creates a new instance of <code>Session</code>.  Sessions should only be
	 * created by the <code>JSch</code> singleton factory, hence the package
	 * access level for the constructor.
	 *
	 * @param host to connect to
	 * @param port to connect to
	 * @param username to connect with
	 * @param config to override global configuration properties
	 */
	Session(String host, int port, String username, SessionConfig config) {
		if( host == null || host.length()==0 ) {
			throw new IllegalArgumentException("SSH host cannot be null/empty:" + host);
		} else if( port < 0 ) {
			throw new IllegalArgumentException("SSH port cannot be less than zero: " + port);
		} else if( username == null || username.length()==0 ) {
			throw new IllegalArgumentException("SSH username cannot be null/empty: " + username);
		}
		_config = config != null ? config : new SessionConfig();
		_host = host;
		_port = port;
		_username = username;
		_versionExchange = new VersionExchange("SSH-2.0-" + JSch.VERSION);
	}

	/**
	 * Starts the SSH session by connecting to the remote host, establishing
	 * a key exchange, determining encryption methods and performing the user
	 * authentication/authorization.
	 *
	 * @throws JSchException if any errors occur
	 */
	public void connect() throws JSchException {
		connect(_timeout, null);
	}

	public void connect(byte[] password) throws JSchException {
		connect(_timeout, password);
	}

	public void connect(int connectTimeout) throws JSchException {
		connect(connectTimeout, null);
	}

	/**
	 * Starts the SSH session by connecting to the remote host, establishing
	 * a key exchange, determining encryption methods and performing the user
	 * authentication/authorization.  The specified timeout in milliseconds is
	 * used when negotiating the connection.
	 *
	 * Note: The connect timeout value will not set the timeout for the session,
	 * it will only be used during the initial connection.  To set the socket
	 * timeout for the entire session, use <code>setTimeout(int)</code>.
	 *
	 * @param connectTimeout in milliseconds
	 * @param password for connecting
	 * @throws JSchException if any errors occur
	 */
	public void connect(int connectTimeout, byte[] password) throws JSchException {
		if( _connected ) {
			throw new JSchException("Session is already connected");
		}
		JSch.getLogger().log(Logger.Level.INFO, "Connecting to " + _host + " port " + _port);

		try {
			/* Create the socket to the remote host and set the input/output
			 * streams. If a proxy instance is set, use the proxy for creating
			 * the socket. If socket factory is set, use factory for creating
			 * socket, otherwise use default socket factory.
			 */
			_io = new IO();	// Create new IO instance for current connection
			if( _proxy == null ) {
				_socket = _socketFactory.createSocket(_host, _port, connectTimeout);
				_io.setInputStream(_socketFactory.getInputStream(_socket));
				_io.setOutputStream(_socketFactory.getOutputStream(_socket));
				_socket.setTcpNoDelay(true);
			} else {
				synchronized( _proxyLock ) {
					_proxy.connect(_socketFactory, _host, _port, connectTimeout);
					_socket = _proxy.getSocket();
					_io.setInputStream(_proxy.getInputStream());
					_io.setOutputStream(_proxy.getOutputStream());
				}
			}

			// Set the socket timeout for reads if timeout is greater than zero
			if( connectTimeout > 0 && _socket != null ) {
				_socket.setSoTimeout(connectTimeout);
			}
			_connected = true;		// Set connected as true (socket is connected)
			_sessionIO = SessionIO.createIO(this, _io.in, _io._out);
			JSch.getLogger().log(Logger.Level.INFO, "Connection established");

			// Exchange version information (send client version, read server version)
			_versionExchange.exchangeVersions(_io.in, _io._out);
			JSch.getLogger().log(Logger.Level.INFO, "Server SSH version: " + getServerVersion());
			JSch.getLogger().log(Logger.Level.INFO, "Client SSH version: " + getClientVersion());

			// Create key exchange and start kex process
			_keyExchange = new KeyExchange(this);
			_sessionId = _keyExchange.runFirstKex();
			_sessionIO.initNewKeys(_keyExchange);

			// Perform user authentication
			if( !UserAuth.authenticateUser(this, password) ) {
				throw new JSchException("User was not authenticated");
			}
			_authenticated = true;

			// Updates the socket timeout to the session timeout, replacing any
			// local timeout set in the connect(timeout) method
			if( (connectTimeout > 0 || _timeout > 0) && _timeout != connectTimeout ) {
				_socket.setSoTimeout(_timeout);
			}

			synchronized( _writeLock ) {
				if( _connected ) {
					_connectThread = _threadFactory.newThread(this);
					_connectThread.setName("Connect thread " + _host + " session");
					_connectThread.setDaemon(_daemonThread);
					_connectThread.start();
				}
			}
		} catch(Exception e) {
			if( _keyExchange != null ) {
				_keyExchange.kexCompleted();
			}
			if( _connected ) {
				try {
					// Make best effort to notify server we are disconnecting
					Buffer buffer = new Buffer(500);
					Packet packet = new Packet(buffer);
					packet.reset();
					buffer.putByte(SSH_MSG_DISCONNECT);
					buffer.putInt(SSH_DISCONNECT_KEY_EXCHANGE_FAILED);	// TODO Value should be dynamic
					buffer.putString(e.toString());
					buffer.putString("en");
					write(packet);
				} catch(Exception ee) {
					/* Ignore close error. */
				} finally {
					disconnect();	// Ensure disconnect in finally!
				}
			}
			_connected = false;
			if( e instanceof JSchException ) {
				throw (JSchException) e;
			}
			throw new JSchException("Failed to connect session: " + e, e);
		} finally {
			Util.bzero(password);
		}
	}

	/**
	 * Requests the server to perform a new key exchange for the session using
	 * any update key exchange proposals set in the session's configuration.
	 *
	 * @throws Exception if any errors occur
	 */
	public void rekey() throws Exception {
		_keyExchange.sendKexInit();
	}

	/**
	 * Opens a new <code>Channel</code> of the specified type.  The type should
	 * be one of the supported types defined by <code>ChannelType</code> as
	 * official SSH channels.
	 *
	 * @see openChannel(ChannelType type)
	 * 
	 * @param type of channel to open
	 * @return new channel instance
	 * @throws JSchException if any errors occur
	 */
	public Channel openChannel(String type) throws JSchException {
		return openChannel(ChannelType.getChannelType(type));
	}

	/**
	 * Creates a new <code>Channel</code> instance of the specified type for
	 * this session.
	 *
	 * Once a <code>Channel</code> has been created, the user must call the
	 * <code>connect()</code> method in order to connect the channel through the
	 * session.
	 *
	 * @param <T> type of channel instance
	 * @param type of channel to open
	 * @return new channel instance
	 * @throws JSchException if the session is down or if the channel cannot be
	 *			opened or if any other unspecified error occurs
	 */
	@SuppressWarnings("unchecked")
	public <T extends Channel> T openChannel(ChannelType type) throws JSchException {
		if( !_connected ) {
			throw new JSchException("Failed to open channel, session is closed");
		}
		try {
			Channel channel = type.createChannel(this);
			channel.init();
			return (T) channel;
		} catch(Exception e) {
			throw new JSchException("Failed to open channel: "+type, e);
		}
	}

	/**
	 * Adds the channel to the session's managed channel pool.  This method
	 * should *ONLY* be called by the constructor of <code>Channel</code>.
	 *
	 * @param channel to add
	 */
	void addChannel(Channel channel) {
		_channels.put(channel.getId(), channel);
	}

	/**
	 * Removes the channel from the session's managed channel pool.  This method
	 * should *ONLY* be called by disconnect() method of <code>Channel</code>.
	 *
	 * @param channel to remove
	 */
	void removeChannel(Channel channel) {
		_channels.remove(channel.getId(), channel);
	}

	/**
	 * Reads from the session's socket input stream into the specified buffer
	 * performing any required decoding and handling any global requests before
	 * returning the input buffer.
	 *
	 * @param buffer to fill with data read in
	 * @return buffer instance passed in
	 * @throws JSchException if any errors occur
	 * @throws IOException if any IO errors occur
	 */
	public Buffer read(final Buffer buffer) throws JSchException, IOException {
		while( true ) {
			_sessionIO.read(buffer);	// Read in packet

			byte type = (byte) (buffer.getCommand() & 0xff);
			if( type == SSH_MSG_DISCONNECT ) {
				buffer.getInt();
				buffer.getShort();
				int reasonCode = buffer.getInt();
				byte[] description = buffer.getString();
				byte[] language = buffer.getString();
				throw new JSchException("SSH_MSG_DISCONNECT: " + reasonCode +
						" " + Util.byte2str(description) + " " + Util.byte2str(language));
			} else if( type == SSH_MSG_IGNORE ) {
				/* Ignore packet as per SSH spec. */
			} else if( type == SSH_MSG_UNIMPLEMENTED ) {
				buffer.getInt();
				buffer.getShort();
				int reasonId = buffer.getInt();
				if( JSch.getLogger().isEnabled(Logger.Level.INFO) ) {
					JSch.getLogger().log(Logger.Level.INFO, "Received SSH_MSG_UNIMPLEMENTED for " + reasonId);
				}
			} else if( type == SSH_MSG_DEBUG ) {
				buffer.getInt();
				buffer.getShort();
				/* TODO Maybe use configuration to enable displaying debug messages?
				 * byte alwaysDisplay = (byte) buf.getByte();
				 * byte[] message = buf.getString();
				 * byte[] language = buf.getString();
				 * System.err.println("SSH_MSG_DEBUG: "+Util.byte2str(message)+" "+Util.byte2str(language));
				 */
			} else if( type == SSH_MSG_CHANNEL_WINDOW_ADJUST ) {
				buffer.getInt();
				buffer.getShort();
				Channel c = _channels.get(buffer.getInt());
				if( c != null ) {
					c.addRemoteWindowSize(buffer.getInt());
				}
			} else if( type == UserAuthProtocol.SSH_MSG_USERAUTH_SUCCESS ) {
				/* Questionable whether this message code should be in general read
				 * method since this should only be received once when authing user
				 */
				_authenticated = true;
				/* Logic is broken checking for both to be null... couldn't compression
				 * exist only in one direction (one null and other instantiated)
				 */
				_sessionIO.initCompressor(_keyExchange.getKexProposal().getCompressionAlgCtoS());
				_sessionIO.initDecompressor(_keyExchange.getKexProposal().getCompressionAlgStoC());
				break;
			} else {
				break;
			}
		}
		return buffer;
	}

	/**
	 * Writes the specified channel packet to the session.
	 *
	 * @param packet
	 * @param channel
	 * @param length
	 * @throws Exception if any errors occur
	 */
	void write(Packet packet, Channel channel, int length) throws Exception {
		while( true ) {
			if( _keyExchange.inKex() ) {
//				if( _timeout > 0L && (System.currentTimeMillis() - _kexStartTime) > _timeout ) {
//					throw new JSchException("Timeout waiting for rekeying process after "+_timeout+"ms");
//				}
				try {
					Thread.sleep(10);
				} catch(InterruptedException e) { /* Ignore error. */ }
				continue;
			}
			synchronized( channel ) {
				if( channel._remoteWindowSize >= length ) {
					channel._remoteWindowSize -= length;
					break;	// Write channel packet immediately
				}
			}
			if( channel._closed || !channel.isConnected() ) {
				throw new IOException("Failed to write to channel, channel is down");
			}

			boolean sendit = false;
			int s = 0;
			byte command = 0;
			int recipient = -1;
			synchronized ( channel ) {
				if( channel._remoteWindowSize > 0 ) {
					long len = channel._remoteWindowSize > length ? length : channel._remoteWindowSize;
					if( len != length ) {
						s = packet.shift((int) len, _sessionIO.getWriteMacSize());
					}
					command = packet.buffer.getCommand();
					recipient = channel.getRecipient();
					length -= len;
					channel._remoteWindowSize -= len;
					sendit = true;
				}
			}
			if( sendit ) {
				_write(packet);
				if( length == 0 ) {
					return;
				}
				packet.unshift(command, recipient, s, length);
			}

			synchronized ( channel ) {
				if( _keyExchange.inKex() ) {
					continue;
				}
				if( channel._remoteWindowSize >= length ) {
					channel._remoteWindowSize -= length;
					break;
				}
				try {
					channel._notifyMe++;
					channel.wait(100);
				} catch(InterruptedException e) {
					/* Ignore error. */
				} finally {
					channel._notifyMe--;
				}
			}
		}
		_write(packet);
	}

	/**
	 * Writes the specified SSH packet to the output stream sending it to the
	 * remote SSH server.  If the session is currently in the process of a key
	 * exchange, then only key exchange packets will be allowed to send; any
	 * other packets will wait until the key exchange is complete.
	 *
	 * @param packet to send
	 * @throws JSchException if any errors occur
	 * @throws IOException if any IO errors occur
	 */
	public void write(Packet packet) throws JSchException, IOException {
		// While in key exchange, any packets being sent which are not part of
		// the exchange will wait until after the exchange is completed
		kexWait:
		while( _keyExchange.inKex() ) {
//			if( _timeout > 0L && (System.currentTimeMillis() - _kexStartTime) > _timeout ) {
//				throw new JSchException("Timeout waiting for rekeying process after "+_timeout+"ms");
//			}
			// Check packet command and only allow kex packets to be sent
			switch( packet.buffer.getCommand() ) {
				case SSH_MSG_KEXINIT:
				case SSH_MSG_NEWKEYS:
				case SSH_MSG_KEXDH_INIT:
				case SSH_MSG_KEXDH_REPLY:	// Same as SSH_MSG_KEX_DH_GEX_GROUP
				case SSH_MSG_KEX_DH_GEX_INIT:
				case SSH_MSG_KEX_DH_GEX_REPLY:
				case SSH_MSG_KEX_DH_GEX_REQUEST:
				case SSH_MSG_DISCONNECT:
					break kexWait;	// Allow key exchange packets to break out of waiting loop
			}
			try {
				Thread.sleep(10);	// Wait until key exchange is complete
			} catch(InterruptedException e) { /* Ignore error. */ }
		}
		_write(packet);	// Send packet to SSH server over socket connection
	}

	private void _write(Packet packet) throws JSchException, IOException {
		synchronized( _writeLock ) {
			_sessionIO.write(packet);
		}
	}
	
	@Override
	public void run() {
		_thread = this;

		Buffer readBuffer = new Buffer();
		Packet readPacket = new Packet(readBuffer);
		Channel channel;
		int[] start = new int[1], length = new int[1];
		int stimeout = 0;

		try {
			while( _connected && _thread != null ) {
				try {
					read(readBuffer);
					stimeout = 0;
				} catch(InterruptedIOException ee) {
					if( !_keyExchange.inKex() && stimeout < _serverAliveCountMax ) {
						sendKeepAliveMsg();
						stimeout++;
						continue;
					} else if( _keyExchange.inKex() && stimeout < _serverAliveCountMax ) {
						stimeout++;
						continue;
					}
					throw ee;
				}

				int msgType = readBuffer.getCommand() & 0xff;
				switch( msgType ) {
					case SSH_MSG_KEXINIT:
						_keyExchange.rekey(readBuffer);
						break;

					case SSH_MSG_NEWKEYS:
						_keyExchange.sendNewKeys();
						_sessionIO.initNewKeys(_keyExchange);
						break;

					case SSH_MSG_CHANNEL_DATA:
						readBuffer.getInt();
						readBuffer.getByte();
						readBuffer.getByte();
						channel = _channels.get(readBuffer.getInt());
						readBuffer.getString(start, length);
						if( channel == null || length[0] == 0 ) {
							break;
						}
						try {
							channel.write(readBuffer.buffer, start[0], length[0]);
						} catch(Exception e) {
							try {	// TODO Error handling?
								channel.disconnect();
							} catch(Exception ee) { /* Ignore error. */ }
							break;
						}
						channel.setLocalWindowSize(channel._localWindowSize - length[0]);
						if( channel._localWindowSize < channel._localWindowMaxSize / 2 ) {
							readPacket.reset();
							readBuffer.putByte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
							readBuffer.putInt(channel.getRecipient());
							readBuffer.putInt(channel._localWindowMaxSize - channel._localWindowSize);
							write(readPacket);
							channel.setLocalWindowSize(channel._localWindowMaxSize);
						}
						break;

					case SSH_MSG_CHANNEL_EXTENDED_DATA:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						readBuffer.getInt();	// data_type_code == 1
						readBuffer.getString(start, length);
						if( channel == null || length[0] == 0 ) {
							break;
						}
						channel.writeExt(readBuffer.buffer, start[0], length[0]);
						
						channel.setLocalWindowSize(channel._localWindowSize - length[0]);
						if( channel._localWindowSize < channel._localWindowMaxSize / 2 ) {
							readPacket.reset();
							readBuffer.putByte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
							readBuffer.putInt(channel.getRecipient());
							readBuffer.putInt(channel._localWindowMaxSize - channel._localWindowSize);
							write(readPacket);
							channel.setLocalWindowSize(channel._localWindowMaxSize);
						}
						break;

					case SSH_MSG_CHANNEL_WINDOW_ADJUST:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						if( channel != null ) {
							channel.addRemoteWindowSize(readBuffer.getInt());
						}
						break;

					case SSH_MSG_CHANNEL_EOF:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						if( channel != null ) {
							channel.eofRemote();
						}
						break;

					case SSH_MSG_CHANNEL_CLOSE:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						if( channel != null ) {
							channel.disconnect();
						}
						break;
						
					case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						channel.setRecipient(readBuffer.getInt());
						channel.setRemoteWindowSize(readBuffer.getUInt());
						channel.setRemotePacketSize(readBuffer.getInt());
						break;

					case SSH_MSG_CHANNEL_OPEN_FAILURE:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						channel.setExitStatus(readBuffer.getInt());
						//buf.getString();  // additional textual information
						//buf.getString();  // language
						channel._closed = true;
						channel._eofRemote = true;
						channel.setRecipient(0);	// exits connect() loop
						break;

					case SSH_MSG_CHANNEL_REQUEST:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						byte[] status = readBuffer.getString();
						boolean reply = readBuffer.getByte() != 0;
						
						if( channel != null ) {
							byte replyType = SSH_MSG_CHANNEL_FAILURE;
							if( "exit-status".equals(Util.byte2str(status)) ) {
								channel.setExitStatus(readBuffer.getInt());	// exit-status
								replyType = SSH_MSG_CHANNEL_SUCCESS;
							}
							if( reply ) {
								readPacket.reset();
								readBuffer.putByte(replyType);
								readBuffer.putInt(channel.getRecipient());
								write(readPacket);
							}
						}
						break;

					case SSH_MSG_CHANNEL_OPEN:
						readBuffer.getInt();
						readBuffer.getShort();
						String channelType = Util.byte2str(readBuffer.getString());

						if( !ChannelType.FORWARDED_TCP_IP.equals(channelType) &&
								!(ChannelType.X11.equals(channelType) && _x11Forwarding) &&
								!(ChannelType.AGENT_FORWARDING.equals(channelType) && _agentForwarding) ) {
							readPacket.reset();
							readBuffer.putByte(SSH_MSG_CHANNEL_OPEN_FAILURE);
							readBuffer.putInt(readBuffer.getInt());	// Recipient
							readBuffer.putInt(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
							readBuffer.putString("");
							readBuffer.putString("");
							write(readPacket);
						} else {
							channel = openChannel(channelType);
							channel.initChannel(readBuffer);

							Thread tmp = _threadFactory.newThread(channel);
							tmp.setName("Channel " + channelType + " " + _host);
							tmp.setDaemon(_daemonThread);
							tmp.start();
						}
						break;
						
					case SSH_MSG_CHANNEL_SUCCESS:
					case SSH_MSG_CHANNEL_FAILURE:
						readBuffer.getInt();
						readBuffer.getShort();
						channel = _channels.get(readBuffer.getInt());
						if( channel != null ) {
							channel._reply = msgType == SSH_MSG_CHANNEL_SUCCESS ? 1 : 0;
						}
						break;

					case SSH_MSG_GLOBAL_REQUEST:	// Ignore global requests?
						readBuffer.getInt();
						readBuffer.getShort();
						readBuffer.getString();				// request name
						if( readBuffer.getByte() != 0 ) {	// reply
							readPacket.reset();
							readBuffer.putByte(SSH_MSG_REQUEST_FAILURE);
							write(readPacket);
						}
						break;

					case SSH_MSG_REQUEST_FAILURE:
					case SSH_MSG_REQUEST_SUCCESS:
						if( _globalRequest.getThread() != null ) {
							_globalRequest.setReply(msgType == SSH_MSG_REQUEST_SUCCESS ? 1 : 0);
							_globalRequest.getThread().interrupt();
						}
						break;

					default:
						throw new IOException("Unknown SSH message type: " + msgType);
				}
			}
		} catch(Exception e) {
			if (e instanceof SocketException && !_connected) {
				// just closing the session
			} else {
				_keyExchange.kexCompleted();
				if( JSch.getLogger().isEnabled(Logger.Level.INFO) ) {
					JSch.getLogger().log(Logger.Level.INFO,
						"Caught an exception, leaving main loop due to " + e, e);
				}
			}
		}
		try {
			disconnect();
		} catch(NullPointerException e) {
			//e.printStackTrace();	// TODO Error handling?
		} catch(Exception e) {
			//e.printStackTrace();	// TODO Error handling?
		}
		_connected = false;
	}

	/**
	 * Disconnects the session including any open channels and closes any open
	 * resources (input and output streams, socket, proxy, etc).
	 */
	public void disconnect() {
		if( !_connected ) {
			return;
		}
		if( JSch.getLogger().isEnabled(Logger.Level.INFO) ) {
			JSch.getLogger().log(Logger.Level.INFO, "Disconnecting from "+_host+" port "+_port);
		}

		// Close all the open channels for this session
		synchronized( _channels ) {
			for( Channel c : new ArrayList<Channel>(_channels.values()) ) {
				c.disconnect();
			}
			_channels.clear();
		}
		_connected = false;

		PortWatcher.delPort(this);
		ChannelForwardedTCPIP.delPort(this);

		synchronized( _writeLock ) {
			if( _connectThread != null ) {
				_connectThread.interrupt();
				_connectThread = null;
			}
		}
		_thread = null;
		try {
			if( _io != null ) {
				_io.close();
				_io = null;
			}
			if( _proxy == null && _socket != null ) {
				_socket.close();
			} else if( _proxy != null ) {
				synchronized ( _proxyLock ) {
					_proxy.close();
				}
				_proxy = null;
			}
		} catch(Exception e) {
			// TODO Error handling?
		}
		_socket = null;
	}

	/**
	 * Sets local port forwarding for the specified local port, host and remote
	 * port and returns the local port used.
	 *
	 * @param localPort
	 * @param host
	 * @param remotePort
	 * @return local port used
	 * @throws JSchException
	 */
	public int setPortForwardingL(int localPort, String host, int remotePort) throws JSchException {
		return setPortForwardingL(SSHConstants.LOCALHOST, localPort, host, remotePort);
	}

	/**
	 * Sets local port forwarding for the specified bind address, local port,
	 * host and remote port and returns the local port used.
	 * 
	 * @param boundAddress
	 * @param localPort
	 * @param host
	 * @param remotePort
	 * @return
	 * @throws JSchException
	 */
	public int setPortForwardingL(String boundAddress, int localPort, String host, int remotePort) throws JSchException {
		return setPortForwardingL(boundAddress, localPort, host, remotePort, null);
	}

	/**
	 * Sets local port forwarding for the specified bind address, local port,
	 * host, remote port and server socket factory and returns the local port
	 * used.
	 *
	 * @param boundAddress
	 * @param localPort
	 * @param host
	 * @param remotePort
	 * @param ssf
	 * @return
	 * @throws JSchException
	 */
	public int setPortForwardingL(String boundAddress, int localPort, String host, int remotePort, ServerSocketFactory ssf) throws JSchException {
		PortWatcher pw = PortWatcher.addPort(this, boundAddress, localPort, host, remotePort, ssf);
		Thread tmp = _threadFactory.newThread(pw);
		tmp.setName("PortWatcher Thread for " + host);
		tmp.setDaemon(_daemonThread);
		tmp.start();
		return pw._localPort;
	}

	/**
	 * Deletes port forwarding for the specified local port.
	 *
	 * @param localPort
	 * @throws JSchException
	 */
	public void delPortForwardingL(int localPort) throws JSchException {
		delPortForwardingL(SSHConstants.LOCALHOST, localPort);
	}

	/**
	 * Deletes port forwarding for the specified bind address and local port.
	 *
	 * @param boundAddress
	 * @param localPort
	 * @throws JSchException
	 */
	public void delPortForwardingL(String boundAddress, int localPort) throws JSchException {
		PortWatcher.delPort(this, boundAddress, localPort);
	}

	/**
	 * Returns a descriptive list of the local ports currently being forwarded.
	 *
	 * @return descriptive list of locally forwarded ports
	 * @throws JSchException
	 */
	public List<String> getPortForwardingL() throws JSchException {
		return PortWatcher.getPortForwarding(this);
	}

	/**
	 * Sets remote port forwarding for the specified remote port, host and local
	 * port.
	 *
	 * @param remotePort
	 * @param host
	 * @param localPort
	 * @throws JSchException
	 */
	public void setPortForwardingR(int remotePort, String host, int localPort) throws JSchException {
		setPortForwardingR(null, remotePort, host, localPort, (SocketFactory) null);
	}

	/**
	 * Sets remote port forwarding for the specified bind address, remote port,
	 * host and local port.
	 *
	 * @param bindAddress
	 * @param remotePort
	 * @param host
	 * @param localPort
	 * @throws JSchException
	 */
	public void setPortForwardingR(String bindAddress, int remotePort, String host, int localPort) throws JSchException {
		setPortForwardingR(bindAddress, remotePort, host, localPort, (SocketFactory) null);
	}

	/**
	 * Sets remote port forwarding for the specified remote port, host, local
	 * port and server socket factory.
	 *
	 * @param remotePort
	 * @param host
	 * @param localPort
	 * @param sf
	 * @throws JSchException
	 */
	public void setPortForwardingR(int remotePort, String host, int localPort, SocketFactory sf) throws JSchException {
		setPortForwardingR(null, remotePort, host, localPort, sf);
	}

	/**
	 * Sets remote port forwarding for the specified bind address, remote port,
	 * host, local port and socket factory.
	 *
	 * @param bindAddress
	 * @param remotePort
	 * @param host
	 * @param localPort
	 * @param sf
	 * @throws JSchException
	 */
	public void setPortForwardingR(String bindAddress, int remotePort, String host, int localPort, SocketFactory sf) throws JSchException {
		ChannelForwardedTCPIP.addPort(this, bindAddress, remotePort, host, localPort, sf);
		setPortForwarding(bindAddress, remotePort);
	}

	/**
	 * Sets remote port forwarding for the specified remote port and deamon.
	 * 
	 * @param remotePort
	 * @param daemon
	 * @throws JSchException
	 */
	public void setPortForwardingR(int remotePort, String daemon) throws JSchException {
		setPortForwardingR(null, remotePort, daemon, null);
	}

	/**
	 * Sets remote port forwarding for the specified remote port, deamon and
	 * argument.
	 * 
	 * @param remotePort
	 * @param daemon
	 * @param arg
	 * @throws JSchException
	 */
	public void setPortForwardingR(int remotePort, String daemon, Object[] arg) throws JSchException {
		setPortForwardingR(null, remotePort, daemon, arg);
	}

	/**
	 * Sets remote port forwarding for the specified bind address, remote port,
	 * daemon and argument.
	 *
	 * @param bindAddress
	 * @param remotePort
	 * @param daemon
	 * @param arg
	 * @throws JSchException
	 */
	public void setPortForwardingR(String bindAddress, int remotePort, String daemon, Object[] arg) throws JSchException {
		ChannelForwardedTCPIP.addPort(this, bindAddress, remotePort, daemon, arg);
		setPortForwarding(bindAddress, remotePort);
	}

	/**
	 * Deletes remote port forwarding for the specified remote port.
	 * 
	 * @param remotePort
	 * @throws JSchException
	 */
	public void delPortForwardingR(int remotePort) throws JSchException {
		ChannelForwardedTCPIP.delPort(this, remotePort);
	}

	/**
	 * Sets port forwarding for the specified bind address and remote port.
	 *
	 * @param bindAddress
	 * @param remotePort
	 * @throws JSchException
	 */
	private void setPortForwarding(String bindAddress, int remotePort) throws JSchException {
		synchronized ( _globalRequest ) {
			Buffer globalBuffer = new Buffer(100); // ??
			Packet globalPacket = new Packet(globalBuffer);
			_globalRequest.setThread(Thread.currentThread());
			try {
				// byte SSH_MSG_GLOBAL_REQUEST 80
				// string "tcpip-forward"
				// boolean want_reply
				// string  address_to_bind
				// uint32  port number to bind
				globalPacket.reset();
				globalBuffer.putByte(SSH_MSG_GLOBAL_REQUEST);
				globalBuffer.putString("tcpip-forward");
				globalBuffer.putByte((byte) 1);	// Want reply true
				globalBuffer.putString(ChannelForwardedTCPIP.normalize(bindAddress));
				globalBuffer.putInt(remotePort);
				write(globalPacket);
			} catch(Exception e) {
				_globalRequest.setThread(null);
				throw new JSchException("Failed to set port forwarding: "+e, e);
			}

			int count = 0, reply = _globalRequest.getReply();
			while( count < 10 && reply == -1 ) {
				try {
					Thread.sleep(1000);	// TODO Make response wait value configurable
				} catch(Exception e) { /* Ignore error. */ }
				count++;
				reply = _globalRequest.getReply();
			}
			_globalRequest.setThread(null);	// Resets reply value as well
			if( reply != 1 ) {
				throw new JSchException("Remote port forwarding failed for listen port " + remotePort);
			}
		}
	}

	/**
	 * Sends an SSH Ignore packet for the session on the transport layer.
	 *
	 * All implementations must understand (and ignore) this message at any time
	 * (after receiving the identification string).  No implementation is
	 * required to send them.  This message can be used as an additional
	 * protection measure against advanced traffic analysis techniques.
	 *
	 * @throws Exception if any errors occur
	 */
	public void sendIgnore() throws Exception {
		Buffer ignoreBuffer = new Buffer(100);
		Packet ignorePacket = new Packet(ignoreBuffer);
		ignorePacket.reset();
		ignoreBuffer.putByte(SSH_MSG_IGNORE);
		write(ignorePacket);
	}

	/**
	 * Sends an SSH keep alive message for the session on the transport layer.
	 *
	 * @throws Exception if any errors occur
	 */
	public void sendKeepAliveMsg() throws Exception {
		Buffer keepAliveBuffer = new Buffer(150);
		Packet keepAlivePacket = new Packet(keepAliveBuffer);
		keepAlivePacket.reset();
		keepAliveBuffer.putByte(SSH_MSG_GLOBAL_REQUEST);
		keepAliveBuffer.putString(KEEP_ALIVE_MSG);
		keepAliveBuffer.putByte((byte) 1);	// Want reply true
		write(keepAlivePacket);
	}

	/**
	 * Sets the <code>UserInfo</code> instance to use for interacting with user.
	 *
	 * @param userinfo
	 */
	public void setUserInfo(UserInfo userinfo) {
		_userinfo = userinfo;
	}

	/**
	 * Returns <code>UserInfo</code> instance used for interacting with user.
	 * @return
	 */
	public UserInfo getUserInfo() {
		return _userinfo;
	}

	/**
	 * Sets the <code>InputStream</code> to use for session.
	 *
	 * @param in
	 */
	public void setInputStream(InputStream in) {
		_in = in;
	}

	/**
	 * Sets the <code>OutputStream</code> to use for session.
	 *
	 * @param out
	 */
	public void setOutputStream(OutputStream out) {
		_out = out;
	}

	/**
	 * Sets the host for X11 forwarding.
	 *
	 * @param host
	 */
	public static void setX11Host(String host) {
		ChannelX11.setHost(host);
	}

	/**
	 * Sets the port for X11 forwarding.
	 *
	 * @param port
	 */
	public static void setX11Port(int port) {
		ChannelX11.setPort(port);
	}

	/**
	 * Sets the cookie for X11 forwarding.
	 *
	 * @param cookie
	 */
	public static void setX11Cookie(String cookie) {
		ChannelX11.setCookie(cookie);
	}

	/**
	 * Returns the session's configuration instance.
	 *
	 * @return session's configuration
	 */
	public SessionConfig getConfig() {
		return _config;
	}

	/**
	 * Sets the <code>SocketFactory</code> instance to use for creating the
	 * <code>Socket</code> to the remote SSH host.  By default the factory is
	 * null, which uses the default socket create method in <code>Util</code>.
	 *
	 * Note: The factory must be set prior to calling connect() if required.
	 *
	 * @param socketFactory
	 */
	public void setSocketFactory(SocketFactory socketFactory) {
		_socketFactory = socketFactory != null ? socketFactory : SocketFactory.DEFAULT_SOCKET_FACTORY;
	}

	/**
	 * Sets the <code>Proxy</code> instance to proxy the SSH session through. By
	 * default the proxy is null, indicating no proxying will be used.
	 *
	 * Note: The proxy must be set prior to calling connect() if required.
	 *
	 * Note: If the session is disconnected, the proxy connection is closed and
	 * the proxy is set to null; it needs to be explicitly set again before
	 * attempting to reconnect if it's required.
	 *
	 * @param proxy to pass SSH connection through
	 */
	public void setProxy(Proxy proxy) {
		_proxy = proxy;
	}

	/**
	 * Returns true if the session is currently connected to the remote host.
	 *
	 * @return true if session is connected to SSH server
	 */
	public boolean isConnected() {
		return _connected;
	}

	/**
	 * Returns true if the session is currently connected && authenticated.
	 *
	 * @return true if authenticated
	 */
	public boolean isAuthenticated() {
		return _authenticated;
	}

	/**
	 * Returns the timeout in milliseconds used on the socket connection to the
	 * remote host.  A value of zero indicates no timeout.
	 *
	 * @see java.net.Socket#setSoTimeout(int)
	 *
	 * @return timeout in milliseconds
	 */
	public int getTimeout() {
		return _timeout;
	}

	/**
	 * Sets the timeout in milliseconds used on the socket connection to the
	 * remote host.  A value of zero indicates no timeout.
	 *
	 * @see java.net.Socket#setSoTimeout(int)
	 *
	 * @param timeout in milliseconds (zero for no timeout)
	 * @throws JSchException if any errors occur
	 */
	public void setTimeout(int timeout) throws JSchException {
		if( timeout < 0 ) {
			throw new JSchException("Invalid timeout value: "+timeout);
		}
		if( _socket != null ) {
			try {
				_socket.setSoTimeout(timeout);
			} catch(Exception e) {
				throw new JSchException("Failed to set socket timeout: "+e, e);
			}
		}
		_timeout = timeout;
	}

	/**
	 * Returns the server version String returned by the SSH server during the
	 * initial connection.
	 *
	 * @return server version
	 */
	public String getServerVersion() {
		return _versionExchange.getServerVersion();
	}

	/**
	 * Returns the client version String.
	 *
	 * @return client version String
	 */
	public String getClientVersion() {
		return _versionExchange.getClientVersion();
	}

	/**
	 * Returns the host key for the server session is currently connected to.
	 * The host key is received during the initial key exchange when session
	 * connects to the remote host.
	 *
	 * @return host key for SSH server
	 */
	public HostKey getHostKey() {
		return _hostKey;
	}

	/**
	 * Returns the host the session connects to.
	 *
	 * @return host of SSH server
	 */
	public String getHost() {
		return _host;
	}

	/**
	 * Returns the port the session connects to.
	 *
	 * @return port of SSH server
	 */
	public int getPort() {
		return _port;
	}

	/**
	 * Returns the username the session uses to connect to the SSH server.
	 *
	 * @return username for session
	 */
	public String getUserName() {
		return _username;
	}

	/**
	 * Returns the host key alias.
	 *
	 * @return host key alias
	 */
	public String getHostKeyAlias() {
		return _hostKeyAlias;
	}

	/**
	 * Sets the host key alias.
	 *
	 * @param hostKeyAlias
	 */
	public void setHostKeyAlias(String hostKeyAlias) {
		_hostKeyAlias = hostKeyAlias;
	}

	/**
	 * Returns the server alive interval in milliseconds.
	 *
	 * @return server alive interval in milliseconds
	 */
	public int getServerAliveInterval() {
		return _serverAliveInterval;
	}

	/**
	 * Sets the server alive interval in milliseconds.
	 *
	 * @param interval
	 * @throws JSchException
	 */
	public void setServerAliveInterval(int interval) throws JSchException {
		setTimeout(interval);
		_serverAliveInterval = interval;
	}

	/**
	 * Returns the server alive count max.
	 *
	 * @return server alive count max
	 */
	public int getServerAliveCountMax() {
		return _serverAliveCountMax;
	}

	/**
	 * Sets the server alive count max.
	 *
	 * @param count
	 */
	public void setServerAliveCountMax(int count) {
		_serverAliveCountMax = count;
	}

	/**
	 * Sets the <code>ThreadFactory</code> to use for creating all worker
	 * threads.
	 *
	 * @param threadFactory
	 */
	public void setThreadFactory(ThreadFactory threadFactory) {
		if( threadFactory != null ) {
			_threadFactory = threadFactory;
		}
	}

	/**
	 * Returns the <code>ThreadFactory</code> to use for creating all worker
	 * threads.
	 *
	 * @return thread factory instance
	 */
	ThreadFactory getThreadFactory() {
		return _threadFactory;
	}

	/**
	 * Sets if the session and any of child threads should run as daemons.
	 *
	 * @param enable
	 */
	public void setDaemonThread(boolean enable) {
		_daemonThread = enable;
	}

	/**
	 * Returns true if this session's thread and it's channels' threads are
	 * running as daemons.
	 *
	 * @return true if threads used for session/channels are running as daemons
	 */
	boolean isDaemonThread() {
		return _daemonThread;
	}

	/**
	 * Returns a defensive copy of the session ID created during the initial key
	 * exchange.
	 *
	 * @return session ID copy
	 */
	public byte[] getSessionId() {
		return Util.copyOf(_sessionId, _sessionId.length);
	}

	/**
	 * Maintains the state of a single global request and it's corresponding
	 * reply from the SSH server for a requesting thread.  A single, final
	 * instance is used to synchronize on to allow only one global request to be
	 * handled at a time.
	 *
	 * TODO SSH spec allows multiple global requests to be sent, responses are
	 * guaranteed to return in the order they are requested... could use queue
	 * to store requests and handle responses rather than blocking
	 *
	 * @author Atsuhiko Yamanaka
	 * @author Michael Laudati
	 */
	private final class GlobalRequestReply {

		/** Thread waiting for a reply from global request. */
		private Thread __thread = null;
		/** Reply returned by the SSH server. */
		private int __reply = -1;

		/**
		 * Sets the thread making the global request which waits for a reply.
		 *
		 * @param thread making global request
		 */
		void setThread(Thread thread) {
			__thread = thread;
			__reply = -1;	// Reset reply for new requestor
		}

		/**
		 * Returns the thread waiting for a reply to a global request.
		 *
		 * @return thread waiting for reply
		 */
		Thread getThread() {
			return __thread;
		}

		/**
		 * Sets the reply to the global request returned by the SSH server.
		 *
		 * @param reply
		 */
		void setReply(int reply) {
			__reply = reply;
		}

		/**
		 * Returns the reply to the global request returned by the SSH server.
		 *
		 * @return reply
		 */
		int getReply() {
			return __reply;
		}
	}

}
