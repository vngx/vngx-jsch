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

import static org.vngx.jsch.constants.ConnectionProtocol.SSH_MSG_CHANNEL_CLOSE;
import static org.vngx.jsch.constants.ConnectionProtocol.SSH_MSG_CHANNEL_DATA;
import static org.vngx.jsch.constants.ConnectionProtocol.SSH_MSG_CHANNEL_EOF;
import static org.vngx.jsch.constants.ConnectionProtocol.SSH_MSG_CHANNEL_OPEN;
import static org.vngx.jsch.constants.ConnectionProtocol.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
import static org.vngx.jsch.constants.ConnectionProtocol.SSH_MSG_CHANNEL_OPEN_FAILURE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.atomic.AtomicInteger;

import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.util.Logger.Level;

/**
 * Default base implementation of a SSH channel and provides a centralized pool
 * for tracking all channel instances.
 *
 * The connection protocol specifies a mechanism to multiplex multiple streams
 * (channels) of data over the confidential and authenticated transport.  It
 * also specifies channels for accessing an interactive shell, for
 * proxy-forwarding various external protocols over the secure transport
 * (including arbitrary TCP/IP protocols), and for accessing secure subsystems
 * on the server host.
 *
 * All terminal sessions, forwarded connections, etc., are channels. Either side
 * may open a channel.  Multiple channels are multiplexed into a single
 * connection.
 *
 * Channels are identified by numbers at each end.  The number referring to a
 * channel may be different on each side.  Requests to open a channel contain
 * the sender's channel number.  Any other channel-related messages contain the
 * recipient's channel number for the channel.
 *
 * Channels are flow-controlled.  No data may be sent to a channel until a
 * message is received to indicate that window space is available.
 *
 * The initial assignments for the 'reason code' values and 'description' values
 * are given in the table below.  Note that the values for the 'reason code' are
 * given in decimal format for readability, but they are actually uint32 values.
 *
 *	Symbolic Name                                  reason code
 *	-------------                                  -----------
 *	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED                1
 *	SSH_OPEN_CONNECT_FAILED                             2
 *	SSH_OPEN_UNKNOWN_CHANNEL_TYPE                       3
 *	SSH_OPEN_RESOURCE_SHORTAGE                          4
 *
 * TODO Once a channel has failed connecting or has disconnected, it cannot be
 * reused to connect again.  Calling connect() methods should throw an exception
 * if the state is closed.
 * 
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public abstract class Channel implements Runnable {

	/** Generator used to create unique IDs for each channel. */
	private final static AtomicInteger ID_GENERATOR = new AtomicInteger();

	/** Session instance channel belongs to. */
	final Session _session;
	/** Unique ID for this channel instance. */
	final int _id;
	/** Type of channel instance. */
	final ChannelType _channelType;
	/** Channel type name in bytes to send to server when opening channel. */
	final byte[] _type;

	/** True if the channel is connected. */
	boolean _connected = false;
	/** Connection timeout in milliseconds (zero indicates no timeout). */
	int _connectTimeout = 0;
	/** Thread which is running the channel instance while connected. */
	Thread _thread;
	/** Channel ID assigned by SSH server to delegate packets. */
	int _recipient = -1;

	/** Local maximum window size. */
	int _localWindowMaxSize = 0x100000;
	/** Local initial window size. */
	int _localWindowSize = _localWindowMaxSize;
	/** Local maximum packet size. */
	int _localMaxPacketSize = 0x4000;
	/** Remote initial window size; */
	long _remoteWindowSize = 0;
	/** Remote maximum packet size. */
	int _remoteMaxPacketSize = 0;

	/** Input/output helper for channel. */
	IO _io;
	/** True if the local output has reached EOF. */
	boolean _eofLocal = false;
	/** True if the remote output has reached EOF. */
	boolean _eofRemote = false;
	/** True if the channel is closed. */
	boolean _closed = false;

	/** Exit status of channel (determined by remote host). */
	int _exitstatus = -1;
	/** Reply status from a channel request (-1 waiting, 0 failure, 1 success). */
	int _reply = 0;
	/** The number of outstanding global requests waiting to be notified for this channel. */
	int _notifyMe = 0;


	/**
	 * Creates a new instance of <code>Channel</code> of the specified type and
	 * adds the instance to the internally maintained pool, incrementing the
	 * pool index and setting the unique ID of this channel.
	 *
	 * @param session to create channel on
	 * @param channelType
	 */
	Channel(Session session, ChannelType channelType) {
		this(session, channelType, channelType._typeName);
	}

	/**
	 * Creates a new instance of <code>Channel</code> of the specified type and
	 * adds the instance to the session's internal channel pool and set the
	 * globally unique ID of this channel.
	 *
	 * Constructor should remain with default access since only Session should
	 * be creating instances.
	 *
	 * @param session the to create channel on
	 * @param channelType of specific channel instance
	 * @param type of channel to send when connecting channel
	 */
	Channel(Session session, ChannelType channelType, String type) {
		_id = ID_GENERATOR.getAndIncrement();	// Generate globally unique ID for channel

		// Set the session of channel and add to session's channel pool
		_session = session;
		_session.addChannel(this);

		// Set channel type and type name sent to SSH server in connect request
		_channelType = channelType;
		_type = Util.str2byte(type);
	}

	/**
	 * Initializes the channel.  Specific implementations can override this
	 * method to perform any initialization before the channel connects. By
	 * default the method does nothing.
	 *
	 * @throws JSchException if any errors occur
	 */
	void init() throws JSchException { }

	/**
	 * Connects the channel through the current session without any timeout.
	 * This is the equivalent of calling <code>connect(0)</code>.
	 *
	 * @throws JSchException if any errors occur
	 */
	public void connect() throws JSchException {
		connect(0);
	}

	/**
	 * Connects the channel through the current session with the specified
	 * timeout in milliseconds.
	 *
	 * @param connectTimeout in milliseconds
	 * @throws JSchException if any errors occur
	 */
	public void connect(int connectTimeout) throws JSchException {
		if( isConnected() ) {
			throw new JSchException("Channel is already connected");
		} else if( !_session.isConnected() ) {
			throw new JSchException("Session is not connected");
		}
		_connectTimeout = connectTimeout;	// Set connection timeout
		try {
			Buffer buffer = new Buffer(100);
			Packet packet = new Packet(buffer);
			// send
			// byte   SSH_MSG_CHANNEL_OPEN(90)
			// string channel type         //
			// uint32 sender channel       // 0
			// uint32 initial window size  // 0x100000(65536)
			// uint32 maxmum packet size   // 0x4000(16384)
			packet.reset();
			buffer.putByte(SSH_MSG_CHANNEL_OPEN);
			buffer.putString(_type);
			buffer.putInt(_id);
			buffer.putInt(_localWindowSize);
			buffer.putInt(_localMaxPacketSize);
			_session.write(packet);

			int retry = 1000;	// Note: Max timeout is 50 seconds (1000 retries * 50ms sleep)
			long start = System.currentTimeMillis();
			while( _recipient == -1 && _session.isConnected() && retry-- > 0 ) {
				if( _connectTimeout > 0L && (System.currentTimeMillis() - start) > _connectTimeout ) {
					throw new JSchException("Failed to open channel: connection timeout after " + _connectTimeout + " ms");
				}
				try { Thread.sleep(50); } catch(Exception ee) { /* Ignore error. */ }
			}
			if( !_session.isConnected() ) {
				throw new JSchException("Failed to open channel: session is not connected");
			} else if( retry == 0 ) {
				throw new JSchException("Failed to open channel: no response");
			}

			/*
			 * At the failure in opening the channel on the sshd,
			 * 'SSH_MSG_CHANNEL_OPEN_FAILURE' will be sent from sshd and it will
			 * be processed in Session#run().
			 */
			if( isClosed() ) {
				throw new JSchException("Failed to open channel: "+_exitstatus);
			}
			_connected = true;
			start();
		} catch(JSchException je) {
			_connected = false;
			disconnect();
			throw je;
		} catch(Exception e) {
			_connected = false;
			disconnect();
			throw new JSchException("Failed to open channel "+getClass().getSimpleName()+": "+_exitstatus, e);
		}
	}

	/**
	 * Starts the channel after connection through the session.  Implementations
	 * can override this method to define specific behavior.
	 *
	 * TODO Should this method be publicly exposed?  It's always called after
	 * a successful connection... should external code ever need to call it?
	 *
	 * @throws JSchException
	 */
	public void start() throws JSchException { }

	/**
	 * Sets the <code>InputStream</code> to read channel input from SSH server.
	 *
	 * @param in stream to read channel data
	 */
	public void setInputStream(InputStream in) {
		_io.setInputStream(in, false);
	}

	/**
	 * Sets the <code>InputStream</code> to read channel input from SSH server
	 * and does not close the stream if specified.
	 *
	 * @param in stream to read channel data
	 * @param dontClose true to not close stream when channel closes
	 */
	public void setInputStream(InputStream in, boolean dontClose) {
		_io.setInputStream(in, dontClose);
	}

	/**
	 * Sets the <code>OutputStream</code> to write channel output to SSH server.
	 *
	 * @param out stream to send channel data
	 */
	public void setOutputStream(OutputStream out) {
		_io.setOutputStream(out, false);
	}

	/**
	 * Sets the <code>OutputStream</code> to write channel output to SSH server
	 * and does not close the stream if specified.
	 *
	 * @param out stream to send channel data
	 * @param dontClose true to not close stream when channel closes
	 */
	public void setOutputStream(OutputStream out, boolean dontClose) {
		_io.setOutputStream(out, dontClose);
	}

	/**
	 * Sets the <code>OutputStream</code> to write extended channel output to
	 * the SSH server.
	 *
	 * @param out stream to send extended output data
	 */
	public void setExtOutputStream(OutputStream out) {
		_io.setExtOutputStream(out, false);
	}

	/**
	 * Sets the <code>OutputStream</code> to write extended channel output to
	 * the SSH server and does not close the stream if specified.
	 *
	 * @param out stream to send extended output data
	 * @param dontClose true to not close stream when channel closes
	 */
	public void setExtOutputStream(OutputStream out, boolean dontClose) {
		_io.setExtOutputStream(out, dontClose);
	}

	/**
	 * Returns a new instance of <code>InputStream</code> for reading channel
	 * output.
	 *
	 * @return new instance of InputStream for reading channel output
	 * @throws IOException if any errors occur
	 */
	public InputStream getInputStream() throws IOException {
		PipedInputStream in = new PipedInputStream(32 * 1024); // TODO this value should be customizable
		_io.setOutputStream(new PipedOutputStream(in), false);
		return in;
	}

	/**
	 * Returns a new instance of <code>InputStream</code> for reading the
	 * extended data of the channel.
	 *
	 * @return new instance of InputStream for reading extended data output
	 * @throws IOException if any errors occur
	 */
	public InputStream getExtInputStream() throws IOException {
		PipedInputStream in = new PipedInputStream(32 * 1024); // TODO this value should be customizable
		_io.setExtOutputStream(new PipedOutputStream(in), false);
		return in;
	}

	/**
	 * Returns a new instance of <code>OutputStream</code> for writing output to
	 * the channel.  A new instance is returned for each invocation rather than
	 * the same instance for use in a multi-threaded environment to preclude the
	 * need for external synchronization.  (Two threads could be writing data to
	 * the channel concurrently)
	 *
	 * @return new instance of OutputStream to write output to channel
	 * @throws IOException if any errors occur
	 */
	public OutputStream getOutputStream() throws IOException {
		return new ChannelOutputStream();
	}

	/**
	 * Returns true if the remote output has reached EOF.
	 *
	 * @return true if remote output is EOF
	 */
	public final boolean isEOF() {
		return _eofRemote;
	}

	/**
	 * Sets the recipient ID sent by the server for the channel instance.
	 *
	 * @param recipient id
	 */
	final void setRecipient(int recipient) {
		_recipient = recipient;
	}

	/**
	 * Returns the recipient ID set by the server for this channel instance.
	 *
	 * @return recipient ID
	 */
	final int getRecipient() {
		return _recipient;
	}

	/**
	 * Sets the local maximum window size in bytes.
	 *
	 * @param localWindowMaxSize in bytes
	 */
	final void setLocalWindowSizeMax(int localWindowMaxSize) {
		_localWindowMaxSize = localWindowMaxSize;
	}

	/**
	 * Sets the local window size in bytes.
	 *
	 * @param localWindowSize in bytes
	 */
	final void setLocalWindowSize(int localWindowSize) {
		_localWindowSize = localWindowSize;
	}

	/**
	 * Sets the local maximum packet size in bytes.
	 *
	 * @param localPacketSize in bytes
	 */
	final void setLocalPacketSize(int localPacketSize) {
		_localMaxPacketSize = localPacketSize;
	}

	/**
	 * Sets the remote window size in bytes.
	 *
	 * @param remoteWindowSize in bytes
	 */
	synchronized final void setRemoteWindowSize(long remoteWindowSize) {
		_remoteWindowSize = remoteWindowSize;
	}

	/**
	 * Adds the specified amount in bytes to the remote window size.
	 *
	 * @param addRemoteWindowSize in bytes
	 */
	synchronized final void addRemoteWindowSize(int addRemoteWindowSize) {
		_remoteWindowSize += addRemoteWindowSize;
		if( _notifyMe > 0 ) {
			notifyAll();
		}
	}

	/**
	 * Sets the remote maximum packet size in bytes.
	 *
	 * @param remotePacketSize in bytes
	 */
	final void setRemotePacketSize(int remotePacketSize) {
		_remoteMaxPacketSize = remotePacketSize;
	}

	/**
	 * Initializes the channel with its recipient ID, the remote window size
	 * and the remote packet size.
	 *
	 * @param buf from session (open channel confirmation response)
	 */
	void initChannel(Buffer buffer) {
		setRecipient(buffer.getInt());
		setRemoteWindowSize(buffer.getUInt());
		setRemotePacketSize(buffer.getInt());
	}

	/**
	 * Writes the specified data to the channel's output stream.
	 *
	 * @param buffer data to write
	 * @param offset
	 * @param length
	 * @throws IOException if any errors occur
	 */
	void write(byte[] buffer, int offset, int length) throws IOException {
		try {	// Only catch null pointer in case IO is null from being closed
			_io.put(buffer, offset, length);
		} catch(NullPointerException e) { /* Ignore error. */ }
	}

	/**
	 * Writes the specified data to the channel's extended data output stream.
	 *
	 * @param buffer data to write
	 * @param offset
	 * @param length
	 * @throws IOException if any errors occur
	 */
	final void writeExt(byte[] buffer, int offset, int length) throws IOException {
		try {	// Only catch null pointer in case IO is null from being closed
			_io.putExt(buffer, offset, length);
		} catch(NullPointerException e) { /* Ignore error. */ }
	}

	/**
	 * Notifies the channel that the remote stream has reached EOF (end of
	 * file) and closes the channel's output stream.
	 */
	final void eofRemote() {
		_eofRemote = true;
		if( _io != null ) {
			_io.closeOut();	// Close output stream since no more data will come
		}
	}

	/**
	 * Sends an EOF (end of file) message for the local stream and sets the
	 * state as EOF locally.
	 */
	final void eof() {
		if( _eofLocal ) {
			return;
		}
		_eofLocal = true;
		try {
			synchronized( this ) {
				if( !_closed ) {
					Buffer buffer = new Buffer(100);
					Packet packet = new Packet(buffer);
					packet.reset();
					buffer.putByte(SSH_MSG_CHANNEL_EOF);
					buffer.putInt(_recipient);
					_session.write(packet);
				}
			}
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.DEBUG, "Failed to send channel EOF local", e);
		}
	}

	/**
	 * Closes the channel.  When a party will no longer send more data to a
	 * channel, it should send SSH_MSG_CHANNEL_EOF.
	 * 
	 *		byte      SSH_MSG_CHANNEL_EOF
	 *		uint32    recipient_channel
	 * 
	 * No explicit response is sent to this message.  However, the application
	 * may send EOF to whatever is at the other end of the channel.  Note that
	 * the channel remains open after this message, and more data may still be
	 * sent in the other direction.  This message does not consume window space
	 * and can be sent even if no window space is available.
	 *
	 * When either party wishes to terminate the channel, it sends
	 * SSH_MSG_CHANNEL_CLOSE.  Upon receiving this message, a party MUST send
	 * back a SSH_MSG_CHANNEL_CLOSE unless it has already sent this message for
	 * the channel.  The channel is considered closed for a party when it has
	 * both sent and received SSH_MSG_CHANNEL_CLOSE, and the party may then
	 * reuse the channel number.  A party MAY send SSH_MSG_CHANNEL_CLOSE without
	 * having sent or received SSH_MSG_CHANNEL_EOF.
	 *
	 *		byte      SSH_MSG_CHANNEL_CLOSE
	 *		uint32    recipient_channel
	 *
	 * This message does not consume window space and can be sent even if no
	 * window space is available.  It is recommended that any data sent before
	 * this message is delivered to the actual destination, if possible.
	 */
	private void close() {
		if( _closed ) {
			return;
		}
		_closed = _eofLocal = _eofRemote = true;

		try {	// Notify SSH server channel is being closed!
			synchronized( this ) {
				Buffer buffer = new Buffer(100);
				Packet packet = new Packet(buffer);
				packet.reset();
				buffer.putByte(SSH_MSG_CHANNEL_CLOSE);
				buffer.putInt(_recipient);
				_session.write(packet);
			}
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.DEBUG, "Failed to send channel close", e);
		}
	}

	/**
	 * Returns true if this channel is closed.
	 *
	 * @return channel is closed for input/output
	 */
	public final boolean isClosed() {
		return _closed;
	}

	/**
	 * Disconnects the channel from the SSH server and cleans up any open
	 * resources.  Calling this method when the channel is not connected has no
	 * effect.
	 */
	public final void disconnect() {
		try {
			synchronized( this ) {
				if( !_connected ) {
					return;
				}
				_connected = false;
			}
			close();			// Switch close/eof flags and send close message to server
			_thread = null;		// Exits any run() loops dependent on thread being not null
			if( _io != null ) {
				_io.close();	// Close any open IO streams for this channel
			}
		} finally {
			// Remove channel from session's pool after closing it
			_session.removeChannel(this);
		}
	}

	/**
	 * Returns true if the channel is currently connected to the SSH server.
	 *
	 * @return true if session and channel are connected to SSH server
	 */
	public final boolean isConnected() {
		return _session != null && _session.isConnected() && _connected;
	}

	/**
	 * Sends the specified signal for this channel to the SSH server.  A signal
	 * can be delivered to the remote process/service using the following
	 * message.  Some systems may not implement signals, in which case they
	 * should ignore this message.
	 *
	 * @param signal to send
	 * @throws Exception if any errors occur
	 */
	public final void sendSignal(String signal) throws Exception {
		RequestSignal request = new RequestSignal();
		request.setSignal(signal);
		request.request(_session, this);
	}

	/**
	 * Sets the exit status code returned by the SSH server for the channel.
	 * This method should only be called by the parent Session when an exit
	 * status message is returned for the channel.
	 *
	 * @param status code
	 */
	final void setExitStatus(int status) {
		_exitstatus = status;
	}

	/**
	 * Returns the exit status code returned by the SSH server for the channel.
	 * When the command running at the other end terminates, the following
	 * message can be sent to return the exit status of the command. Returning
	 * the status is recommended.  No acknowledgement is sent for this message.
	 * The channel needs to be closed with SSH_MSG_CHANNEL_CLOSE after this
	 * message.
	 *
	 * The remote command may also terminate violently due to a signal. Such a
	 * condition can be indicated by the following message.  A zero 
	 * 'exit_status' usually means that the command terminated successfully.
	 *
	 * @return exit status code
	 */
	public final int getExitStatus() {
		return _exitstatus;
	}

	/**
	 * Returns the <code>Session</code> instance this channel is opened on.
	 *
	 * @return session instance
	 */
	public final Session getSession() {
		return _session;
	}

	/**
	 * Returns the unique ID for this channel.
	 *
	 * @return unique ID for channel
	 */
	public final int getId() {
		return _id;
	}

	/**
	 * Returns the channel type.
	 *
	 * @return channel type
	 */
	public final ChannelType getType() {
		return _channelType;
	}

	/**
	 * Sends a channel open confirmation message to the SSH server indicating
	 * the channel was successfully opened.
	 *
	 * @throws Exception if any errors occur
	 */
	final void sendOpenConfirmation() throws Exception {
		// byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
		// uint32    recipient channel
		// uint32    sender channel
		// uint32    initial window size
		// uint32    maximum packet size
		// ....      channel type specific data follows
		Buffer buffer = new Buffer(100);
		Packet packet = new Packet(buffer);
		packet.reset();
		buffer.putByte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
		buffer.putInt(_recipient);
		buffer.putInt(_id);
		buffer.putInt(_localWindowSize);
		buffer.putInt(_localMaxPacketSize);
		_session.write(packet);
	}

	/**
	 * Sends a channel open failure message to the SSH server with the specified
	 * reason code.  A channel open failure message should be sent whenever a
	 * channel fails to open.
	 *
	 * @param reasonCode to send to server
	 */
	final void sendOpenFailure(int reasonCode) {
		/* Wrap the send in a try/catch to prevent any errors from stopping the
		 * channel from completing it's disconnect clean up.
		 */
		try {
			// byte      SSH_MSG_CHANNEL_OPEN_FAILURE
			// uint32    recipient channel
			// uint32    reason code
			// string    description in ISO-10646 UTF-8 encoding [RFC3629]
			// string    language tag [RFC3066]
			Buffer buffer = new Buffer(100);
			Packet packet = new Packet(buffer);
			packet.reset();
			buffer.putByte(SSH_MSG_CHANNEL_OPEN_FAILURE);
			buffer.putInt(_recipient);
			buffer.putInt(reasonCode);
			buffer.putString("open failed");
			buffer.putString("");
			_session.write(packet);
		} catch(Exception e) {
			/* Ignore error, don't bubble exception. */
			JSch.getLogger().log(Level.WARN, "Failed to send channel open failure", e);
		}
	}

	/**
	 * Implementation of <code>OutputStream</code> for writing output to this
	 * channel.
	 *
	 * @author Atsuhiko Yamanaka
	 * @author Michael Laudati
	 */
	final class ChannelOutputStream extends OutputStream {

		/** Current length of data in stream ready to be sent/flushed. */
		private int __dataLen = 0;
		/** Buffer for sending output through channel. */
		private Buffer __outBuffer;
		/** Packet for sending output through channel. */
		private Packet __outPacket;
		/** True if this output stream is currently closed. */
		private boolean __closed = false;
		/** Temporary buffer for writing single byte of data. */
		private final byte[] __b = new byte[1];

		/**
		 * Initializes the stream for sending output over channel.
		 *
		 * @throws IOException
		 */
		private synchronized void init() throws IOException {
			// Initialize the buffer and packet instances
			__outBuffer = new Buffer(_remoteMaxPacketSize);
			__outPacket = new Packet(__outBuffer);

			// Check if output buffer is too small for writing data (based on remote packet size)
			if( __outBuffer.buffer.length - (14 + 0) - 32 - 20 <= 0 ) {
				__outBuffer = null;
				__outPacket = null;
				throw new IOException("Failed to initialize output of channel, remote packet size too small");
			}
		}

		@Override
		public void write(int b) throws IOException {
			__b[0] = (byte) b;
			write(__b, 0, 1);
		}

		@Override
		public void write(byte[] buffer, int offset, int length) throws IOException {
			if( __closed ) {
				throw new IOException("Channel OutputStream already closed");
			} else if( __outPacket == null ) {
				init();
			}

			while( length > 0 ) {
				int writeLen = length;
				if( length > __outBuffer.buffer.length - (14 + __dataLen) - 32 - 20 ) {
					writeLen = __outBuffer.buffer.length - (14 + __dataLen) - 32 - 20;
				}
				if( writeLen <= 0 ) {
					flush();
					continue;
				}

				System.arraycopy(buffer, offset, __outBuffer.buffer, 14 + __dataLen, writeLen);
				__dataLen += writeLen;
				offset += writeLen;
				length -= writeLen;
			}
		}

		@Override
		public void flush() throws IOException {
			if( __closed ) {
				throw new IOException("Channel OutputStream already closed");
			} else if( __dataLen == 0 ) {
				return;	// Nothing to write
			}
			__outPacket.reset();
			__outBuffer.putByte(SSH_MSG_CHANNEL_DATA);
			__outBuffer.putInt(_recipient);
			__outBuffer.putInt(__dataLen);
			__outBuffer.skip(__dataLen);
			try {
				int len = __dataLen;
				__dataLen = 0;	// Reset data length
				_session.write(__outPacket, Channel.this, len);
			} catch(Exception e) {
				close();	// Close the stream if an error has occurred
				throw new IOException("Failed to flush channel data: "+e, e);
			}
		}

		@Override
		public void close() throws IOException {
			if( __closed ) {
				return;
			}
			// If there's data, flush it before closing
			if( __dataLen > 0 ) {
				if( __outPacket == null ) {
					try {
						init();
					} catch(IOException e) {
						return;	// close should finish silently
					}
				}
				flush();
			}
			Channel.this.eof();	// Notify SSH server end of file for channel
			__closed = true;
		}
	}

}
