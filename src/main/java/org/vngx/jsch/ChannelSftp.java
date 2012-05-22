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
import static org.vngx.jsch.constants.SftpProtocol.*;

import org.vngx.jsch.exception.JSchException;
import org.vngx.jsch.exception.SftpException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementation of <code>ChannelSession</code> for opening a SFTP channel
 * which runs as a subsystem for "sftp".
 *
 * This protocol provides secure file transfer (and more generally file system
 * access). It is designed so that it could be used to implement a secure remote
 * file system service as well as a secure file transfer service.
 *
 * In general, this protocol follows a simple request-response model. Each
 * request and response contains a sequence number and multiple requests may be
 * pending simultaneously.  There are a relatively large number of different
 * request messages, but a small number of possible response messages.  Each
 * request has one or more response messages that may be returned in result
 * (e.g., a read either returns data or reports error status).
 *
 * The SSH File Transfer Protocol has changed over time, before it's
 * standardization.  The following is a description of the incompatible changes
 * between different versions.
 *   10.1 Changes between versions 3 and 2
 *		- The SSH_FXP_READLINK and SSH_FXP_SYMLINK messages were added.
 *		- The SSH_FXP_EXTENDED and SSH_FXP_EXTENDED_REPLY messages were added.
 *		- The SSH_FXP_STATUS message was changed to include fields `error
 *			message' and `language tag'.
 *   10.2 Changes between versions 2 and 1
 *		- The SSH_FXP_RENAME message was added.
 *   10.3 Changes between versions 1 and 0
 *		- Implementation changes, no actual protocol changes.
 *
 * TODO For performance, since SFTP channel is not thread-safe/synchronized,
 * instance variables should be used to cache state to reduce the amount of
 * redundant traffic and object creation; for instance, a single header instance
 * could be reused across a the entire SFTP session.
 *
 * <p>Note: This class is not thread-safe and should be externally synchronized.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class ChannelSftp extends ChannelSession {

	/** Version of SFTP client sent to server during initialization. */
	private static final int CLIENT_VERSION = 3;
	/** Maximum message length in bytes. */
	private static final int MAX_MSG_LENGTH = 256 * 1024;
	/** Constant boolean to indicate if file separator is the back slash. */
	private static final boolean FS_IS_BS = (byte) File.separatorChar == '\\';
	/** Constant string for character set for UTF-8. */
	private static final String UTF8 = "UTF-8";


	public static final int OVERWRITE = 0;

	public static final int RESUME = 1;

	public static final int APPEND = 2;

	/** Buffer for reading and writing SFTP traffic. */
	private Buffer _buffer;
	/** Packet used for sending SFTP outbound traffic. */
	private Packet _packet;
	/** Header instance to reuse for reading responses for performance. */
	private final Header _header = new Header();
	/** Server version received during start of SFTP session. */
	private int _serverVersion;
	/** Extensions received from the server. */
	private Map<String,String> _extensions;
	/** Input stream for SFTP channel to read incoming channel data. */
	private InputStream _io_in;
	/** Current sequence number of SFTP packet sent to server. */
	private int _seq = 1;
	
	/** Filename encoding to use when converting Strings/byte[]. */
	private String _fileEncoding = UTF8;
	/** True if filename encoding is UTF-8. */
	private boolean _utf8 = true;

	/** Remote home directory for user. */
	private String _home;
	/** Remote current working directory. */
	private String _cwd;
	/** Local current working directory. */
	private String _lcwd;


	/**
	 * Creates a new instance of <code>ChannelSftp</code>.
	 *
	 * @param session
	 */
	ChannelSftp(Session session) {
		super(session, ChannelType.SFTP);
	}

	@Override
	public void start() throws JSchException {
		try {
			PipedOutputStream pos = new PipedOutputStream();
			_io.setOutputStream(pos);
			_io.setInputStream(new PipedInputStream(pos, 32 * 1024));	// TODO make pipe size configurable
			_io_in = _io.in;
			if( _io_in == null ) {
				throw new JSchException("Channel is down");
			}

			new RequestSftp().request(_session, this);
			_buffer = new Buffer(_remoteMaxPacketSize);
			_packet = new Packet(_buffer);

			// send SSH_FXP_INIT
			sendINIT();

			// receive SSH_FXP_VERSION
			readHeader();
			if( _header.length > MAX_MSG_LENGTH ) {
				throw new SftpException(SSH_FX_FAILURE, "Received message is too long: " + _header.length);
			}
			_serverVersion = _header.rid;	// Retrieve version from header

			if( _header.length > 0 ) {
				_extensions = new HashMap<String,String>();
				fill(_buffer, _header.length);	// read in extension data
				byte[] extensionName, extensionData;
				while( _header.length > 0 ) {
					extensionName = _buffer.getString();
					extensionData = _buffer.getString();
					_header.length -= 4 + extensionName.length + 4 + extensionData.length;
					_extensions.put(Util.byte2str(extensionName), Util.byte2str(extensionData));
				}
			}

			// Set local current working directory and home directory after connecting
			_lcwd = new File(".").getCanonicalPath();	// TODO Should be configurable location
			_home = Util.byte2str(_realpath(""), _fileEncoding);
			_cwd = _home;
		} catch(JSchException e) {
			throw e;
		} catch(Exception e) {
			throw new JSchException("Failed to start ChannelSftp", e);
		}
	}

	/**
	 * Quits the SFTP session and closes the channel.  (Same as
	 * <code>exit()</code>).
	 */
	public void quit() {
		disconnect();
	}

	/**
	 * Exits the SFTP session and closes the channel.  (Same as
	 * <code>quit()</code>)
	 */
	public void exit() {
		disconnect();
	}

	/**
	 * Changes the local current working directory to the specified path.
	 *
	 * @param path to set as local current working directory
	 * @throws SftpException if any errors occur or path is not valid
	 */
	public void lcd(String path) throws SftpException {
		path = localAbsolutePath(path);
		if( !new File(path).isDirectory() ) {
			throw new SftpException(SSH_FX_NO_SUCH_FILE, "Failed to lcd, directory does not exist: "+path);
		}
		try {
			path = new File(path).getCanonicalPath();
		} catch(Exception e) { /* Ignore error. */ }
		_lcwd = path;
	}

	/**
	 * Changes the remote current working directory to the specified path.
	 *
	 * @param path to set as remote current working directory
	 * @throws SftpException if any errors occur of path is not valid
	 */
	public void cd(String path) throws SftpException {
		try {
			path = isUnique(remoteAbsolutePath(path));

			byte[] realPath = _realpath(path);
			SftpATTRS attr = _stat(realPath);
			if( (attr.getFlags() & SSH_FILEXFER_ATTR_PERMISSIONS) == 0 ) {
				throw new SftpException(SSH_FX_FAILURE, "Failed to cd (permission denied): " + path);
			} else if( !attr.isDir() ) {
				throw new SftpException(SSH_FX_FAILURE, "Failed to cd (not a directory): " + path);
			}
			_cwd = Util.byte2str(realPath, _fileEncoding);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to cd path: "+path, e);
		}
	}

	public void put(String src, String dst) throws SftpException {
		put(src, dst, null, OVERWRITE);
	}

	public void put(String src, String dst, int mode) throws SftpException {
		put(src, dst, null, mode);
	}

	public void put(String src, String dst, SftpProgressMonitor monitor) throws SftpException {
		put(src, dst, monitor, OVERWRITE);
	}

	public void put(String src, String dst, SftpProgressMonitor monitor, int mode) throws SftpException {
		src = localAbsolutePath(src);
		dst = remoteAbsolutePath(dst);

		try {
			List<String> matches = globRemote(dst);
			if( matches.size() != 1 ) {
				if( matches.isEmpty() ) {
					if( isPattern(dst) ) {
						throw new SftpException(SSH_FX_FAILURE, "Invalid destination for put: "+dst);
					} else {
						dst = Util.unquote(dst);
					}
				}
				throw new SftpException(SSH_FX_FAILURE, "Destination is not unique: "+matches);
			} else {
				dst = matches.get(0);
			}

			boolean isRemoteDir = isRemoteDir(dst);
			matches = globLocal(src);

			StringBuffer dstsb = null;
			if( isRemoteDir ) {
				if( !dst.endsWith("/") ) {
					dst += "/";
				}
				dstsb = new StringBuffer(dst);
			} else if( matches.size() > 1 ) {
				throw new SftpException(SSH_FX_FAILURE, "Copying multiple files, but the destination is missing or a file.");
			}

			String _dst;
			for( String _src : matches ) {
				if( isRemoteDir ) {
					int i = _src.lastIndexOf(File.separatorChar);
					if( FS_IS_BS ) {
						int ii = _src.lastIndexOf('/');
						if( ii != -1 && ii > i ) {
							i = ii;
						}
					}
					if( i == -1 ) {
						dstsb.append(_src);
					} else {
						dstsb.append(_src.substring(i + 1));
					}
					_dst = dstsb.toString();
					dstsb.delete(dst.length(), _dst.length());
				} else {
					_dst = dst;
				}

				long sizeOfDest = 0;
				if( mode == RESUME ) {
					try {
						sizeOfDest = _stat(_dst).getSize();
					} catch(Exception eee) {
						// TODO Error handling?
					}
					long sizeOfSrc = new File(_src).length();
					if( sizeOfSrc < sizeOfDest ) {
						throw new SftpException(SSH_FX_FAILURE, "failed to resume for " + _dst);
					} else if( sizeOfSrc == sizeOfDest ) {
						return;
					}
				}

				if( monitor != null ) {
					monitor.init(SftpProgressMonitor.PUT, _src, _dst, (new File(_src)).length());
					if( mode == RESUME ) {
						monitor.count(sizeOfDest);
					}
				}
				FileInputStream fis = null;
				try {
					_put(fis = new FileInputStream(_src), _dst, monitor, mode);
				} finally {
					if( fis != null ) {
						try { fis.close(); } catch(IOException ie) { /* Ignore error. */ }
					}
				}
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to put: "+src, e);
		}
	}

	public void put(InputStream src, String dst) throws SftpException {
		put(src, dst, null, OVERWRITE);
	}

	public void put(InputStream src, String dst, int mode) throws SftpException {
		put(src, dst, null, mode);
	}

	public void put(InputStream src, String dst, SftpProgressMonitor monitor) throws SftpException {
		put(src, dst, monitor, OVERWRITE);
	}

	public void put(InputStream src, String dst, SftpProgressMonitor monitor, int mode) throws SftpException {
		try {
			dst = remoteAbsolutePath(dst);

			List<String> matches = globRemote(dst);
			if( matches.size() != 1 ) {
				if( matches.isEmpty() ) {
					if( isPattern(dst) ) {
						throw new SftpException(SSH_FX_FAILURE, "Invalid destination for put: "+dst);
					} else {
						dst = Util.unquote(dst);
					}
				}
				throw new SftpException(SSH_FX_FAILURE, "Destination is not unique: "+matches);
			} else {
				dst = matches.get(0);
			}
			if( isRemoteDir(dst) ) {
				throw new SftpException(SSH_FX_FAILURE, dst + " is a directory");
			}

			_put(src, dst, monitor, mode);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to put: "+e, e);
		}
	}

	private void _put(InputStream src, String dst, SftpProgressMonitor monitor, int mode) throws SftpException {
		try {
			byte[] dstb = Util.str2byte(dst, _fileEncoding);
			long skip = 0;
			if( mode == RESUME || mode == APPEND ) {
				try {
					skip = _stat(dstb).getSize();
				} catch(Exception eee) {
					// TODO Error handling?
					//System.err.println(eee);
				}
			}
			if( mode == RESUME && skip > 0 ) {
				long skipped = src.skip(skip);
				if( skipped < skip ) {
					throw new SftpException(SSH_FX_FAILURE, "failed to resume for " + dst);
				}
			}

			if( mode == OVERWRITE ) {
				sendOPENW(dstb);
			} else {
				sendOPENA(dstb);
			}
			readResponse();
			if( _header.type != SSH_FXP_HANDLE ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}

			byte[] handle = _buffer.getString();         // handle
			byte[] data = null;

			boolean dontcopy = true;	// WHA?!!
			if( !dontcopy ) {
				data = new byte[_buffer.buffer.length - (5 + 13 + 21 + handle.length + (32 + 20 /* padding and mac */))];
			}

			long offset = 0;
			if( mode == RESUME || mode == APPEND ) {
				offset += skip;
			}

			int startid = _seq;
			int ackid = _seq;
			int ackcount = 0;
			while( true ) {
				int nread = 0;
				int s = 0;
				int datalen = 0;
				int count = 0;

				if( !dontcopy ) {
					datalen = data.length - s;
				} else {
					data = _buffer.buffer;
					s = 5 + 13 + 21 + handle.length;
					datalen = _buffer.buffer.length - s
							- 32 - 20; // padding and mac
				}

				do {
					nread = src.read(data, s, datalen);
					if( nread > 0 ) {
						s += nread;
						datalen -= nread;
						count += nread;
					}
				} while( datalen > 0 && nread > 0 );
				if( count <= 0 ) {
					break;
				}

				int _i = count;
				while( _i > 0 ) {
					_i -= sendWRITE(handle, offset, data, 0, _i);
					if( (_seq - 1) == startid || _io_in.available() >= 1024 ) {
						while( _io_in.available() > 0 ) {
							ackid = readResponseOk();
							if( startid > ackid || ackid > _seq - 1 ) {
								if( ackid == _seq ) {
									System.err.println("ack error: startid=" + startid + " seq=" + _seq + " _ackid=" + ackid);
								} else {
									throw new SftpException(SSH_FX_FAILURE, "ack error: startid=" + startid + " seq=" + _seq + " _ackid=" + ackid);
								}
							}
							ackcount++;
						}
					}
				}
				offset += count;
				if( monitor != null && !monitor.count(count) ) {
					break;
				}
			}
			int _ackcount = _seq - startid;
			while( _ackcount > ackcount ) {
				readResponseOk();
				ackcount++;
			}
			if( monitor != null ) {
				monitor.end();
			}
			_sendCLOSE(handle);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to put: "+dst, e);
		}
	}

	public OutputStream put(String dst) throws SftpException {
		return put(dst, (SftpProgressMonitor) null, OVERWRITE);
	}

	public OutputStream put(String dst, int mode) throws SftpException {
		return put(dst, (SftpProgressMonitor) null, mode);
	}

	public OutputStream put(String dst, SftpProgressMonitor monitor, int mode) throws SftpException {
		return put(dst, monitor, mode, 0);
	}

	public OutputStream put(String dst, SftpProgressMonitor monitor, int mode, long offset) throws SftpException {
		try {
			dst = isUnique(remoteAbsolutePath(dst));
			if( isRemoteDir(dst) ) {
				throw new SftpException(SSH_FX_FAILURE, dst + " is a directory");
			}
			byte[] dstb = Util.str2byte(dst, _fileEncoding);

			long skip = 0;
			if( mode == RESUME || mode == APPEND ) {
				try {
					skip = _stat(dstb).getSize();
				} catch(Exception eee) {
					//System.err.println(eee);
				}
			}

			if( mode == OVERWRITE ) {
				sendOPENW(dstb);
			} else {
				sendOPENA(dstb);
			}

			readResponse();
			if( _header.type != SSH_FXP_HANDLE ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}
			if( mode == RESUME || mode == APPEND ) {
				offset += skip;
			}
			byte[] handle = _buffer.getString();         // handle
			return new PutOutputStream(handle, offset, monitor);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to put: "+dst, e);
		}
	}

	public void get(String src, String dst) throws SftpException {
		get(src, dst, null, OVERWRITE);
	}

	public void get(String src, String dst, SftpProgressMonitor monitor) throws SftpException {
		get(src, dst, monitor, OVERWRITE);
	}

	public void get(String src, String dst, SftpProgressMonitor monitor, int mode) throws SftpException {
		src = remoteAbsolutePath(src);
		dst = localAbsolutePath(dst);

		boolean dstExists = false, error = false;
		String _dst = null;
		try {
			List<String> matches = globRemote(src);
			if( matches.isEmpty() ) {
				throw new SftpException(SSH_FX_NO_SUCH_FILE, "No such file: "+src);
			}

			File dstFile = new File(dst);
			boolean isDstDir = dstFile.isDirectory();
			StringBuffer dstsb = null;
			if( isDstDir ) {
				if( !dst.endsWith(File.separator) ) {
					dst += File.separator;
				}
				dstsb = new StringBuffer(dst);
			} else if( matches.size() > 1 ) {
				throw new SftpException(SSH_FX_FAILURE, "Copying multiple files, but destination is missing or a file.");
			}

			for( String _src : matches ) {
				SftpATTRS attr = _stat(_src);
				if( attr.isDir() ) {
					throw new SftpException(SSH_FX_FAILURE, "Not supported to get directory " + _src);
				}

				_dst = null;
				if( isDstDir ) {
					int i = _src.lastIndexOf('/');
					if( i == -1 ) {
						dstsb.append(_src);
					} else {
						dstsb.append(_src.substring(i + 1));
					}
					_dst = dstsb.toString();
					dstsb.delete(dst.length(), _dst.length());
				} else {
					_dst = dst;
				}

				File _dstFile = new File(_dst);
				if( mode == RESUME ) {
					long sizeOfSrc = attr.getSize();
					long sizeOfDst = _dstFile.length();
					if( sizeOfDst > sizeOfSrc ) {
						throw new SftpException(SSH_FX_FAILURE, "Failed to resume for " + _dst);
					} else if( sizeOfDst == sizeOfSrc ) {
						return;	// Nothing to resume, already have full file
					}
				}

				if( monitor != null ) {
					monitor.init(SftpProgressMonitor.GET, _src, _dst, attr.getSize());
					if( mode == RESUME ) {
						monitor.count(_dstFile.length());
					}
				}

				FileOutputStream fos = null;
				dstExists = _dstFile.exists();
				try {
					fos = new FileOutputStream(_dst, mode != OVERWRITE);
					_get(_src, fos, monitor, mode, new File(_dst).length());
				} finally {
					if( fos != null ) {
						try { fos.close(); } catch(IOException ie) { /* Ignore error. */ }
					}
				}
			}
		} catch(SftpException e) {
			error = true;
			throw e;
		} catch(Exception e) {
			error = true;
			throw new SftpException(SSH_FX_FAILURE, "Failed to get src: "+src, e);
		} finally {
			if( error && !dstExists && _dst != null ) {
				File _dstFile = new File(_dst);
				if( _dstFile.exists() && _dstFile.length() == 0 ) {
					_dstFile.delete();
				}
			}
		}
	}

	public void get(String src, OutputStream dst) throws SftpException {
		get(src, dst, null, OVERWRITE, 0);
	}

	public void get(String src, OutputStream dst, SftpProgressMonitor monitor) throws SftpException {
		get(src, dst, monitor, OVERWRITE, 0);
	}

	public void get(String src, OutputStream dst, SftpProgressMonitor monitor, int mode, long skip) throws SftpException {
		try {
			src = isUnique(remoteAbsolutePath(src));

			if( monitor != null ) {
				monitor.init(SftpProgressMonitor.GET, src, "??", _stat(src).getSize());
				if( mode == RESUME ) {
					monitor.count(skip);
				}
			}
			_get(src, dst, monitor, mode, skip);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to get src: "+src, e);
		}
	}

	private void _get(String src, OutputStream dst, SftpProgressMonitor monitor, int mode, long skip) throws SftpException {
		byte[] srcb = Util.str2byte(src, _fileEncoding);
		try {
			sendOPENR(srcb);
			readResponse();
			if( _header.type != SSH_FXP_HANDLE ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}

			byte[] handle = _buffer.getString();         // filename
			long offset = mode == RESUME ? skip : 0;
			int requestLen = 0;
			loop:
			while( true ) {
				requestLen = _buffer.buffer.length - 13;
				if( _serverVersion == 0 ) {
					requestLen = 1024;
				}
				sendREAD(handle, offset, requestLen);
				readHeader();

				if( _header.type == SSH_FXP_STATUS ) {
					fill(_buffer, _header.length);
					int i = _buffer.getInt();
					if( i == SSH_FX_EOF ) {
						break loop;
					}
					throwStatusError(_buffer, i);
				}
				if( _header.type != SSH_FXP_DATA ) {
					break loop;
				}

				_buffer.rewind();
				fill(_buffer.buffer, 0, 4);
				_header.length -= 4;
				int i = _buffer.getInt();   // length of data
				int foo = i;

				while( foo > 0 ) {
					int bar = foo > _buffer.buffer.length ? _buffer.buffer.length : foo;
					if( (i = _io_in.read(_buffer.buffer, 0, bar)) < 0 ) {
						break loop;
					}
					int bytesRead = i;
					dst.write(_buffer.buffer, 0, bytesRead);

					offset += bytesRead;
					foo -= bytesRead;

					if( monitor != null ) {
						if( !monitor.count(bytesRead) ) {
							while( foo > 0 ) {
								i = _io_in.read(_buffer.buffer, 0, (_buffer.buffer.length < foo ? _buffer.buffer.length : foo));
								if( i <= 0 ) {
									break;
								}
								foo -= i;
							}
							break loop;
						}
					}

				}
			}
			dst.flush();

			if( monitor != null ) {
				monitor.end();
			}
			_sendCLOSE(handle);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to get src: "+src, e);
		}
	}

	public InputStream get(String src) throws SftpException {
		return get(src, null, 0L);
	}

	public InputStream get(String src, SftpProgressMonitor monitor) throws SftpException {
		return get(src, monitor, 0L);
	}

	public InputStream get(String src, SftpProgressMonitor monitor, long skip) throws SftpException {
		try {
			src = isUnique(remoteAbsolutePath(src));
			byte[] srcb = Util.str2byte(src, _fileEncoding);
			if( monitor != null ) {
				monitor.init(SftpProgressMonitor.GET, src, "??", _stat(srcb).getSize());
			}

			sendOPENR(srcb);
			readResponse();
			if( _header.type != SSH_FXP_HANDLE ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}
			byte[] handle = _buffer.getString();         // handle

			return new GetInputStream(skip, handle, monitor);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to get src: "+src, e);
		}
	}

	public List<LsEntry> ls(String path) throws SftpException {
		try {
			path = remoteAbsolutePath(path);
			
			int index = path.lastIndexOf('/');
			String dir = Util.unquote(path.substring(0, index + 1));
			String sPattern = path.substring(index + 1);

			// If pattern has included '*' or '?', we need to convert
			// to UTF-8 string before globbing.
			byte[] bPattern = null;
			boolean wildcardPattern = isPattern(sPattern);

			if( wildcardPattern ) {
				bPattern = Util.str2byte(sPattern);	// UTF-8 encoded
			} else {
				String upath = Util.unquote(path);
				if( _stat(upath).isDir() ) {
					dir = upath;
				} else {
					// If we could generate longname by ourself,
					// we don't have to use openDIR.
					if( _utf8 ) {
						bPattern = Util.unquote(Util.str2byte(sPattern));
					} else {
						sPattern = Util.unquote(sPattern);
						bPattern = Util.str2byte(sPattern, _fileEncoding);
					}
				}
			}

			sendOPENDIR(Util.str2byte(dir, _fileEncoding));
			readResponse();
			if( _header.type != SSH_FXP_HANDLE ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}

			byte[] handle = _buffer.getString();         // handle
			List<LsEntry> lsEntries = new ArrayList<LsEntry>();
			while( true ) {
				sendREADDIR(handle);
				readHeader();
				if( _header.type != SSH_FXP_STATUS && _header.type != SSH_FXP_NAME ) {
					throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
				} else if( _header.type == SSH_FXP_STATUS ) {
					fill(_buffer, _header.length);
					int i = _buffer.getInt();
					if( i == SSH_FX_EOF ) {
						break;
					}
					throwStatusError(_buffer, i);
				}

				_buffer.rewind();
				fill(_buffer.buffer, 0, 4);
				_header.length -= 4;
				int count = _buffer.getInt();
				_buffer.reset();

				while( count > 0 ) {
					if( _header.length > 0 ) {
						_buffer.shift();
						int j = (_buffer.buffer.length > (_buffer.index + _header.length)) ? _header.length : (_buffer.buffer.length - _buffer.index);
						int i = fill(_buffer.buffer, _buffer.index, j);
						_buffer.index += i;
						_header.length -= i;
					}
					byte[] bFilename = _buffer.getString();
					String sFilename = Util.byte2str(bFilename, _fileEncoding);
					byte[] bLongname = _serverVersion <= 3 ? _buffer.getString() : null;
					SftpATTRS attrs = SftpATTRS.getATTR(_buffer);

					boolean found = false;
					if( bPattern == null ) {
						found = true;
					} else if( !wildcardPattern ) {
						found = Arrays.equals(bPattern, bFilename);
					} else {
						found = Util.glob(bPattern, _utf8 ? bFilename : Util.str2byte(sFilename, UTF8));
					}

					if( found ) {
						// TODO: need to generate long name from attrs for sftp protocol 4(and later)
						String sLongname = bLongname == null ?
							(attrs.toString() + " " + sFilename) :
							Util.byte2str(bLongname, _fileEncoding);
						lsEntries.add(new LsEntry(sFilename, sLongname, attrs));
					}
					count--;
				}
			}
			_sendCLOSE(handle);
			return lsEntries;
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to ls path: "+path, e);
		}
	}

	public String readlink(String path) throws SftpException {
		if( _serverVersion < 3 ) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED, "The remote SFTP server is too old to support readlink operation");
		}
		try {
			path = isUnique(remoteAbsolutePath(path));

			sendREADLINK(Util.str2byte(path, _fileEncoding));
			readResponse();
			if( _header.type != SSH_FXP_NAME ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}

			int count = _buffer.getInt();       // count
			byte[] filename = null;
			for( int i = 0; i < count; i++ ) {
				filename = _buffer.getString();	// absolute path
				if( _serverVersion <= 3 ) {
					_buffer.getString();		// long filename
				}
				SftpATTRS.getATTR(_buffer);		// dummy attribute
			}
			return Util.byte2str(filename, _fileEncoding);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to readlink path: "+path, e);
		}
	}

	public void symlink(String oldpath, String newpath) throws SftpException {
		if( _serverVersion < 3 ) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED, "The remote SFTP server is too old to support symlink operation");
		}
		try {
			oldpath = isUnique(remoteAbsolutePath(oldpath));
			newpath = remoteAbsolutePath(newpath);

			if( isPattern(newpath) ) {
				throw new SftpException(SSH_FX_FAILURE, "Failed to symlink, new path is invalid: "+newpath);
			}
			newpath = Util.unquote(newpath);

			sendSYMLINK(Util.str2byte(oldpath, _fileEncoding), Util.str2byte(newpath, _fileEncoding));
			readResponseOk();
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to symlink path: "+oldpath, e);
		}
	}

	public void rename(String oldpath, String newpath) throws SftpException {
		if( _serverVersion < 2 ) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED, "The remote SFTP server is too old to support rename operation");
		}
		try {
			oldpath = isUnique(remoteAbsolutePath(oldpath));
			newpath = remoteAbsolutePath(newpath);

			List<String> matches = globRemote(newpath);
			if( matches.size() >= 2 ) {
				throw new SftpException(SSH_FX_FAILURE, "Failed to rename path, found too many matches: "+matches);
			} else if( matches.size() == 1 ) {
				newpath = matches.get(0);
			} else {
				if( isPattern(newpath) ) {
					throw new SftpException(SSH_FX_FAILURE, "Failed to rename path, new path is invalid: "+newpath);
				}
				newpath = Util.unquote(newpath);
			}

			sendRENAME(Util.str2byte(oldpath, _fileEncoding), Util.str2byte(newpath, _fileEncoding));
			readResponseOk();
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to rename path: "+oldpath, e);
		}
	}

	public void rm(final String path) throws SftpException {
		try {
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				sendREMOVE(Util.str2byte(remotePath, _fileEncoding));
				readResponseOk();
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to rm path: "+path, e);
		}
	}

	public void chgrp(int gid, String path) throws SftpException {
		try {
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				SftpATTRS attr = _stat(remotePath);
				attr.setFLAGS(0);
				attr.setUIDGID(attr.getUId(), gid);
				_setStat(remotePath, attr);
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to chgrp path: "+path, e);
		}
	}

	public void chown(int uid, String path) throws SftpException {
		try {
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				SftpATTRS attr = _stat(remotePath);
				attr.setFLAGS(0);
				attr.setUIDGID(uid, attr.getGId());
				_setStat(remotePath, attr);
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to chown path: "+path, e);
		}
	}

	public void chmod(int permissions, String path) throws SftpException {
		try {
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				SftpATTRS attr = _stat(remotePath);
				attr.setFLAGS(0);
				attr.setPERMISSIONS(permissions);
				_setStat(remotePath, attr);
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to chmod path: "+path, e);
		}
	}

	public void setMtime(String path, int mtime) throws SftpException {
		try {
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				SftpATTRS attr = _stat(remotePath);
				attr.setFLAGS(0);
				attr.setACMODTIME(attr.getAccessTime(), mtime);
				_setStat(remotePath, attr);
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to set mtime path: "+path, e);
		}
	}

	public void rmdir(String path) throws SftpException {
		try {
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				sendRMDIR(Util.str2byte(remotePath, _fileEncoding));
				readResponseOk();
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to rmdir path :"+path, e);
		}
	}

	public void mkdir(String path) throws SftpException {
		try {
			sendMKDIR(Util.str2byte(remoteAbsolutePath(path), _fileEncoding), null);
			readResponseOk();
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to mkdir path: "+path, e);
		}
	}

	public SftpATTRS stat(String path) throws SftpException {
		try {
			return _stat(isUnique(remoteAbsolutePath(path)));
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to stat path: "+path, e);
		}
	}

	private SftpATTRS _stat(String path) throws SftpException {
		return _stat(Util.str2byte(path, _fileEncoding));
	}

	private SftpATTRS _stat(byte[] path) throws SftpException {
		try {
			sendSTAT(path);
			readResponse();
			if( _header.type != SSH_FXP_ATTRS ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}
			return SftpATTRS.getATTR(_buffer);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to stat path: "+path, e);
		}
	}

	private boolean isRemoteDir(String path) {
		try {
			return _stat(path).isDir();
		} catch(Exception e) {
			return false;
		}
	}

	public SftpATTRS lstat(String path) throws SftpException {
		try {
			return _lstat(isUnique(remoteAbsolutePath(path)));
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to lstat path: "+path, e);
		}
	}

	private SftpATTRS _lstat(String path) throws SftpException {
		try {
			sendLSTAT(Util.str2byte(path, _fileEncoding));
			readResponse();
			if( _header.type != SSH_FXP_ATTRS ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}
			return SftpATTRS.getATTR(_buffer);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to lstat path: "+path, e);
		}
	}

	/**
	 * Returns the real path for the specified remote path as determined by the
	 * server.
	 *
	 * @param path to retrieve
	 * @return absolute remote path from server
	 * @throws SftpException if any SFTP errors occur
	 * @throws IOException if any read errors occur
	 * @throws Exception if any write errors occur
	 */
	private byte[] _realpath(String path) throws SftpException, IOException, Exception {
		sendREALPATH(Util.str2byte(path, _fileEncoding));
		readResponse();
		if( _header.type != SSH_FXP_NAME ) {
			throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
		}

		byte[] str = null;
		int count = _buffer.getInt();
		while( count-- > 0 ) {
			str = _buffer.getString();		// absolute path
			if( _serverVersion <= 3 ) {
				_buffer.getString();		// long filename
			}
			SftpATTRS.getATTR(_buffer);		// dummy attribute
		}
		return str;
	}

	public void setStat(String path, SftpATTRS attr) throws SftpException {
		try {
			// For each remote path found for specified path, set the attributes
			for( String remotePath : globRemote(remoteAbsolutePath(path)) ) {
				_setStat(remotePath, attr);
			}
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to set stat for path: "+path, e);
		}
	}

	private void _setStat(String path, SftpATTRS attr) throws SftpException {
		try {
			sendSETSTAT(Util.str2byte(path, _fileEncoding), attr);
			readResponseOk();
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to set stat for path: "+path, e);
		}
	}

	/**
	 * Returns the user's current working directory path on the remote server.
	 *
	 * @return current working directory path
	 */
	public String pwd() {
		return _cwd;
	}

	/**
	 * Returns the local current working directory path on client.
	 *
	 * @return local current working directory
	 */
	public String lpwd() {
		return _lcwd;
	}

	/**
	 * Returns the user's home directory path on the remote server.
	 *
	 * @return home directory path
	 */
	public String getHome() {
		return _home;
	}

	/**
	 * Returns the client SFTP version.
	 *
	 * @return client SFTP version
	 */
	public String version() {
		return String.valueOf(CLIENT_VERSION);
	}

	/**
	 * Returns the server SFTP version established during initial connection.
	 *
	 * @return server SFTP version
	 * @throws SftpException if SFTP channel is not connected
	 */
	public int getServerVersion() throws SftpException {
		if( !isConnected() ) {
			throw new SftpException(SSH_FX_FAILURE, "The channel is not connected");
		}
		return _serverVersion;
	}

	/**
	 * Sends the INIT request to start the SFTP session by sending this client's
	 * SFTP version.
	 *
	 * @throws Exception if any errors occur
	 */
	private void sendINIT() throws Exception {
		putHEAD(SSH_FXP_INIT, 5);
		_buffer.putInt(CLIENT_VERSION);
		_session.write(_packet, this, 5 + 4);
	}

	/**
	 * Sends a real path request for the specified path.
	 *
	 * @param path to request real path
	 * @throws Exception if any errors occur
	 */
	private void sendREALPATH(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_REALPATH, path);
	}

	private void sendSTAT(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_STAT, path);
	}

	private void sendLSTAT(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_LSTAT, path);
	}

	private void sendSETSTAT(byte[] path, SftpATTRS attr) throws Exception {
		putHEAD(SSH_FXP_SETSTAT, 9 + path.length + attr.length());
		_buffer.putInt(_seq++);
		_buffer.putString(path);	// path
		attr.dump(_buffer);
		_session.write(_packet, this, 9 + path.length + attr.length() + 4);
	}

	private void sendREMOVE(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_REMOVE, path);
	}

	private void sendMKDIR(byte[] path, SftpATTRS attr) throws Exception {
		putHEAD(SSH_FXP_MKDIR, 9 + path.length + (attr != null ? attr.length() : 4));
		_buffer.putInt(_seq++);
		_buffer.putString(path);	// path
		if( attr != null ) {
			attr.dump(_buffer);
		} else {
			_buffer.putInt(0);
		}
		_session.write(_packet, this, 9 + path.length + (attr != null ? attr.length() : 4) + 4);
	}

	private void sendRMDIR(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_RMDIR, path);
	}

	private void sendSYMLINK(byte[] p1, byte[] p2) throws Exception {
		sendPacketPath(SSH_FXP_SYMLINK, p1, p2);
	}

	private void sendREADLINK(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_READLINK, path);
	}

	private void sendOPENDIR(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_OPENDIR, path);
	}

	private void sendREADDIR(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_READDIR, path);
	}

	private void sendRENAME(byte[] p1, byte[] p2) throws Exception {
		sendPacketPath(SSH_FXP_RENAME, p1, p2);
	}

	private void sendCLOSE(byte[] path) throws Exception {
		sendPacketPath(SSH_FXP_CLOSE, path);
	}

	private void _sendCLOSE(byte[] handle) throws Exception {
		sendCLOSE(handle);
		readResponseOk();
	}

	private void sendOPENR(byte[] path) throws Exception {
		sendOPEN(path, SSH_FXF_READ);
	}

	private void sendOPENW(byte[] path) throws Exception {
		sendOPEN(path, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC);
	}

	private void sendOPENA(byte[] path) throws Exception {
		sendOPEN(path, SSH_FXF_WRITE |/*SSH_FXF_APPEND|*/ SSH_FXF_CREAT);
	}

	private void sendOPEN(byte[] path, int mode) throws Exception {
		putHEAD(SSH_FXP_OPEN, 17 + path.length);
		_buffer.putInt(_seq++);
		_buffer.putString(path);
		_buffer.putInt(mode);
		_buffer.putInt(0);			// attrs
		_session.write(_packet, this, 17 + path.length + 4);
	}

	/**
	 * Sends an SFTP packet path request with the specified SFTP protocol code
	 * and path value.
	 *
	 * @param fxp SFTP protocol code
	 * @param path value
	 * @throws Exception if any errors occur writing packet to session
	 */
	private void sendPacketPath(byte fxp, byte[] path) throws Exception {
		putHEAD(fxp, 9 + path.length);
		_buffer.putInt(_seq++);
		_buffer.putString(path);
		_session.write(_packet, this, 9 + path.length + 4);
	}

	private void sendPacketPath(byte fxp, byte[] path1, byte[] path2) throws Exception {
		putHEAD(fxp, 13 + path1.length + path2.length);
		_buffer.putInt(_seq++);
		_buffer.putString(path1);
		_buffer.putString(path2);
		_session.write(_packet, this, 13 + path1.length + path2.length + 4);
	}

	private int sendWRITE(byte[] handle, long offset, byte[] data, int start, int length) throws Exception {
		int _length = length;
		_packet.reset();
		if( _buffer.buffer.length < _buffer.index + 13 + 21 + handle.length + length
				+ 32 + 20 ) { // padding and mac
			_length = _buffer.buffer.length - (_buffer.index + 13 + 21 + handle.length
				+ 32 + 20 ); // padding and mac
		}

		putHEAD(SSH_FXP_WRITE, 21 + handle.length + _length);	// 14
		_buffer.putInt(_seq++);									//  4
		_buffer.putString(handle);								//  4+handle.length
		_buffer.putLong(offset);								//  8
		if( _buffer.buffer != data ) {
			_buffer.putString(data, start, _length);			//  4+_length
		} else {
			_buffer.putInt(_length);
			_buffer.skip(_length);
		}
		_session.write(_packet, this, 21 + handle.length + _length + 4);
		return _length;
	}

	private void sendREAD(byte[] handle, long offset, int length) throws Exception {
		putHEAD(SSH_FXP_READ, 21 + handle.length);
		_buffer.putInt(_seq++);
		_buffer.putString(handle);
		_buffer.putLong(offset);
		_buffer.putInt(length);
		_session.write(_packet, this, 21 + handle.length + 4);
	}

	/**
	 * Puts the header in the current buffer for a SFTP packet.
	 *
	 * @param type of SFTP code request
	 * @param length of SFTP data in bytes
	 * @throws Exception if any errors occur
	 */
	private void putHEAD(byte type, int length) {
		// byte      SSH_MSG_CHANNEL_DATA
		// uint32    recipient channel
		// uint32    total packet length
		// uint32    sftp data length
		// byte      SFTP request code
		// ....      channel type specific data follows
		_packet.reset();
		_buffer.putByte(SSH_MSG_CHANNEL_DATA);
		_buffer.putInt(_recipient);
		_buffer.putInt(length + 4);
		_buffer.putInt(length);
		_buffer.putByte(type);
	}

	/**
	 * Globs (pattern searches) the remote file system for the specified path or
	 * pattern.
	 *
	 * @param path (or pattern) to search for
	 * @return matching absolute remote paths
	 * @throws Exception if any errors occur
	 */
	private List<String> globRemote(final String path) throws Exception {
		int index = path.lastIndexOf('/');
		if( index < 0 ) {  // Return if not path is not an absolute path
			return Arrays.asList(Util.unquote(path));
		}

		String dir = Util.unquote(path.substring(0, index+1)); //(index == 0 ? 1 : index)));
		String sPattern = path.substring(index + 1);
		if( !isPattern(sPattern) ) {	// Return if path is not a pattern
			return Arrays.asList(dir + Util.unquote(sPattern));
		}

		sendOPENDIR(Util.str2byte(dir, _fileEncoding));
		readResponse();
		if( _header.type != SSH_FXP_HANDLE ) {
			throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
		}

		List<String> matches = new ArrayList<String>();
		byte[] bPattern = Util.str2byte(sPattern, UTF8);
		byte[] handle = _buffer.getString();         // filename
		while( true ) {
			sendREADDIR(handle);
			readHeader();
			if( _header.type == SSH_FXP_STATUS ) {
				fill(_buffer, _header.length);
				break;
			} else if( _header.type != SSH_FXP_NAME ) {
				throw new SftpException(SSH_FX_FAILURE, "Invalid FXP response: "+_header.type);
			}

			_buffer.rewind();
			fill(_buffer.buffer, 0, 4);
			_header.length -= 4;
			int i, count = _buffer.getInt();
			_buffer.reset();

			while( count > 0 ) {
				if( _header.length > 0 ) {
					_buffer.shift();
					int j = (_buffer.buffer.length > (_buffer.index + _header.length)) ? _header.length : (_buffer.buffer.length - _buffer.index);
					if( (i = _io_in.read(_buffer.buffer, _buffer.index, j)) <= 0 ) {
						break;
					}
					_buffer.index += i;
					_header.length -= i;
				}

				byte[] bFilename = _buffer.getString();	// absolute path
				String sFilename = Util.byte2str(bFilename, _fileEncoding);
				if( _serverVersion <= 3 ) {
					_buffer.getString();				// file longname
				}
				SftpATTRS.getATTR(_buffer);				// Read in file attributes

				if( Util.glob(bPattern, _utf8 ? bFilename : Util.str2byte(sFilename)) ) {
					matches.add(dir + sFilename);
				}
				count--;
			}
		}
		_sendCLOSE(handle);
		return matches;
	}

	private List<String> globLocal(final String path) throws Exception {
		byte[] bPath = Util.str2byte(path, UTF8);
		int i = bPath.length - 1;
		while( i >= 0 ) {
			if( bPath[i] != '*' && bPath[i] != '?' ) {
				i--;
				continue;
			} else if( !FS_IS_BS && i > 0 && bPath[i - 1] == '\\' ) {
				i--;
				if( i > 0 && bPath[i - 1] == '\\' ) {
					i-=2;
					continue;
				}
			}
			break;
		}
		if( i < 0 ) {
			return Arrays.asList(FS_IS_BS ? path : Util.unquote(path));
		}

		while( i >= 0 ) {
			if( bPath[i] == File.separatorChar || (FS_IS_BS && bPath[i] == '/') ) {
				break;	// On Windows, '/' is also the separator.
			}
			i--;
		}
		if( i < 0 ) {
			return Arrays.asList(FS_IS_BS ? path : Util.unquote(path));
		}

		byte[] dir;
		if( i == 0 ) {
			dir = new byte[]{(byte) File.separatorChar};
		} else {
			dir = new byte[i];
			System.arraycopy(bPath, 0, dir, 0, i);
		}

		byte[] pattern = new byte[bPath.length - i - 1];
		System.arraycopy(bPath, i + 1, pattern, 0, pattern.length);
		try {
			List<String> matches = new ArrayList<String>();
			String pdir = Util.byte2str(dir) + File.separator;
			for( String filename : new File(Util.byte2str(dir)).list() ) {
				if( Util.glob(pattern, Util.str2byte(filename)) ) {
					matches.add(pdir + filename);
				}
			}
			return matches;
		} catch(Exception e) {
			throw new IOException("Failed to globLocal path: "+path, e);
		}
	}

	private void throwStatusError(Buffer buf, int status) throws SftpException {
		if( _serverVersion >= 3 &&			// WindRiver's sftp will send invalid
				buf.getLength() >= 4 ) {	// SSH_FXP_STATUS packet.
			throw new SftpException(status, "SFTP status error: " + Util.byte2str(buf.getString(), UTF8));
		} else {
			throw new SftpException(status, "SFTP status error: unknown");
		}
	}

	/**
	 * Fills the specified buffer through the specified length from the SFTP
	 * input stream.
	 *
	 * @param buf to fill
	 * @param len to fill
	 * @throws IOException if any read errors occur
	 */
	private void fill(Buffer buf, int len) throws IOException {
		buf.reset();
		fill(buf.buffer, 0, len);
		buf.skip(len);
	}

	/**
	 * Fills the specified buffer from the offset s through length len by
	 * reading from the SFTP input stream.
	 *
	 * @param buf to fill with data from SFTP input stream
	 * @param s offset
	 * @param len length
	 * @return amount of bytes read
	 * @throws IOException if any read errors occur
	 */
	private int fill(byte[] buf, int s, int len) throws IOException {
		int i, offset = s;
		while( len > 0 ) {
			if( (i = _io_in.read(buf, s, len)) <= 0 ) {
				throw new IOException("SFTP InputStream is closed");
			}
			s += i;
			len -= i;
		}
		return s - offset;
	}

	/**
	 * Reads the header information from the SFTP input stream and fills the 
	 * specified buffer with any associated data after the header.  Checks the
	 * SFTP protocol response code and throws a status error if sent from
	 * server.
	 *
	 * @return header info from buffer
	 * @throws IOException if any read errors occur
	 * @throws SftpException if status error is returned from server
	 */
	private void readResponse() throws IOException, SftpException {
		readHeader();				// Read header data from input
		fill(_buffer, _header.length);	// Read rest of data from input stream into buffer
		if( _header.type == SSH_FXP_STATUS ) {
			throwStatusError(_buffer, _buffer.getInt());	// Throw status error
		}
	}

	private int readResponseOk() throws IOException, SftpException {
		readHeader();				// Read header data from input
		fill(_buffer, _header.length);	// Read rest of data from input stream into buffer
		if( _header.type != SSH_FXP_STATUS ) {
			throw new SftpException(SSH_FX_FAILURE, "Invalid FXP status response: "+_header.type);
		}
		int status = _buffer.getInt();
		if( status != SSH_FX_OK ) {
			throwStatusError(_buffer, status);
		}
		return _header.rid;	// Return acknowledge ID from header
	}
	
	/**
	 * Reads the header information from the instance buffer into the instance
	 * header.
	 *
	 * @throws IOException if any read errors occur
	 */
	private void readHeader() throws IOException {
		_buffer.rewind();
		fill(_buffer.buffer, 0, 9);	// Read first 9 bytes containing header
		_header.length = _buffer.getInt() - 5;
		_header.type   = (byte) (_buffer.getByte() & 0xff);
		_header.rid    = _buffer.getInt();
	}

	/**
	 * Returns the remote absolute path from the specified relative path.
	 *
	 * @param path
	 * @return absolute path (properly formatted)
	 * @throws SftpException
	 */
	private String remoteAbsolutePath(String path) {
		if( path.charAt(0) == '/' ) {
			return path;
		}
		return _cwd + (_cwd.charAt(_cwd.length()-1) == '/' ? path : '/' + path);
	}

	/**
	 * Returns the local absolute path for the specified path.
	 *
	 * @param path
	 * @return absolute local path
	 */
	private String localAbsolutePath(String path) {
		if( new File(path).isAbsolute() ) {
			return path;
		}
		return _lcwd + (_lcwd.endsWith(File.separator) ? path : File.separator + path);
	}

	/**
	 * This method will check if the given string can be expanded to the
	 * unique string.  If it can be expanded to multiple files, SftpException
	 * will be thrown.
	 *
	 * @return the returned string is unquoted
	 */
	private String isUnique(String path) throws SftpException, Exception {
		List<String> matches = globRemote(path);
		if( matches.size() != 1 ) {
			throw new SftpException(SSH_FX_FAILURE, path + " is not unique: " + matches);
		}
		return matches.get(0);
	}

	/**
	 * Sets the file name encoding to use.  By default, filename encoding is
	 * UTF-8.  If the SFTP server version does not support changing the filename
	 * encoding than a <code>SftpException</code> will be thrown.
	 *
	 * @param encoding to use for path/file names
	 * @throws SftpException if not connected or server doesn't support
	 *			different encodings
	 */
	public void setFilenameEncoding(String encoding) throws SftpException {
		if( getServerVersion() > 3 && !UTF8.equals(encoding) ) {
			throw new SftpException(SSH_FX_FAILURE, "The encoding cannot be changed for this sftp server version");
		}
		_fileEncoding = encoding;
		_utf8 = UTF8.equals(_fileEncoding);
	}

	public String getExtension(String key) {
		return _extensions != null ? _extensions.get(key) : null;
	}

	/**
	 * Returns the absolute path from the server for the specified path.
	 *
	 * @param path to check
	 * @return absolute path from server
	 * @throws SftpException if any errors occur
	 */
	public String realpath(String path) throws SftpException {
		try {
			return Util.byte2str(_realpath(remoteAbsolutePath(path)), _fileEncoding);
		} catch(SftpException e) {
			throw e;
		} catch(Exception e) {
			throw new SftpException(SSH_FX_FAILURE, "Failed to realpath path: "+path, e);
		}
	}

	private static boolean isPattern(byte[] path) {
		int i = path.length - 1;
		while( i >= 0 ) {
			if( path[i] == '*' || path[i] == '?' ) {
				if( i > 0 && path[i - 1] == '\\' ) {
					i--;
					if( i > 0 && path[i - 1] == '\\' ) {    // \\* or \\?
						break;
					}
				} else {
					break;
				}
			}
			i--;
		}
		return !(i < 0);
	}

	private static boolean isPattern(String path) {
		return isPattern(Util.str2byte(path, UTF8));
	}

	/**
	 * Simple class for storing SFTP packet header information.
	 *
	 * @author Atsuhiko Yamanaka
	 * @author Michael Laudati
	 */
	final class Header {
		/** Packet length from header. */
		int length;
		/** Packet type code from header. */
		byte type;
		/** Recipient ID from header. */
		int rid;
	}

	/**
	 * Represents an entry returned by the 'ls' SFTP command containing
	 * information about a file or folder on the remote system.
	 *
	 * @author Atsuhiko Yamanaka
	 * @author Michael Laudati
	 */
	public final class LsEntry implements Comparable<LsEntry> {

		/** File name of entry. */
		private final String __filename;
		/** Long name of entry. */
		private final String __longname;
		/** SFTP attributes for file/folder. */
		private final SftpATTRS __attrs;

		/**
		 * Creates a new instance of <code>LsEntry</code> with the specified
		 * properties.  Constructor should remain package access since instances
		 * should only be created by the SFTP channel.
		 *
		 * @param filename of entry
		 * @param longname of entry
		 * @param attrs entry
		 */
		LsEntry(String filename, String longname, SftpATTRS attrs) {
			__filename = filename;
			__longname = longname;
			__attrs = attrs;
		}

		/**
		 * Returns the file name of the entry.
		 *
		 * @return file name
		 */
		public String getFilename() {
			return __filename;
		}

		/**
		 * Returns the long name of the entry.
		 *
		 * @return long name of entry
		 */
		public String getLongname() {
			return __longname;
		}

		/**
		 * Returns the SFTP attributes for the entry.
		 *
		 * @return attributes of entry
		 */
		public SftpATTRS getAttrs() {
			return __attrs;
		}

		@Override
		public String toString() {
			return __longname;
		}

		@Override
		public int compareTo(LsEntry entry) {
			return __filename.compareTo(entry.getFilename());
		}

	}

	/**
	 * Implementation of <code>OutputStream</code> for writing data out to the
	 * SFTP channel for a PUT operation, which creates a file on the remote host
	 * and fills it with the data from this output stream.
	 *
	 * @author Atsuhiko Yamanaka
	 * @author Michael Laudati
	 */
	private final class PutOutputStream extends OutputStream {

		private boolean __init = true;
		private boolean __closed = false;
		private int __startId = 0;
		private int __ackCount = 0;
		private int __writeCount = 0;
		private long __offset;
		private final byte[] __data = new byte[1];
		private final byte[] __handle;
		private final SftpProgressMonitor __monitor;


		PutOutputStream(byte[] handle, long offset, SftpProgressMonitor monitor) {
			__handle = handle;
			__offset = offset;
			__monitor = monitor;
		}

		@Override
		public void write(byte[] b) throws IOException {
			write(b, 0, b.length);
		}

		@Override
		public void write(byte[] b, int s, int len) throws IOException {
			if( __init ) {
				__startId = _seq;
				__init = false;
			}
			if( __closed ) {
				throw new IOException("OutputStream already closed");
			}

			try {
				int _len = len, ackId;
				while( _len > 0 ) {
					int sent = sendWRITE(__handle, __offset, b, s, _len);
					__writeCount++;
					__offset += sent;
					s += sent;
					_len -= sent;
					if( (_seq - 1) == __startId || _io_in.available() >= 1024 ) {
						while( _io_in.available() > 0 ) {
							ackId = readResponseOk();
							if( __startId > ackId || ackId > _seq - 1 ) {
								throw new SftpException(SSH_FX_FAILURE, "Invalid ack ID: "+ackId);
							}
							__ackCount++;
						}
					}
				}
				if( __monitor != null && !__monitor.count(len) ) {
					close();
					throw new IOException("OutputStream canceled by user");
				}
			} catch(IOException e) {
				throw e;
			} catch(Exception e) {
				throw new IOException(e);
			}
		}

		@Override
		public void write(int b) throws IOException {
			__data[0] = (byte) b;
			write(__data, 0, 1);
		}

		@Override
		public void flush() throws IOException {
			if( __closed ) {
				throw new IOException("OutputStream already closed");
			}
			if( !__init ) {
				try {
					while( __writeCount > __ackCount ) {
						readResponseOk();
						__ackCount++;
					}
				} catch(SftpException e) {
					throw new IOException(e);
				}
			}
		}

		@Override
		public void close() throws IOException {
			if( __closed ) {
				return;
			}
			flush();
			__closed = true;
			if( __monitor != null ) {
				__monitor.end();
			}
			try {
				_sendCLOSE(__handle);
			} catch(IOException e) {
				throw e;
			} catch(Exception e) {
				throw new IOException("Failed to close OutputStream", e);
			}
		}

	}

	/**
	 * Implementation of <code>InputStream</code> for reading input from the
	 * SFTP channel supplied from a GET operation.
	 *
	 * @author Atsuhiko Yamanaka
	 * @author Michael Laudati
	 */
	private final class GetInputStream extends InputStream {

		private long __offset;
		private boolean __closed = false;
		private int __restLength = 0;
		private byte[] __restByte = new byte[1024];
		private final byte[] __data = new byte[1];
		private final SftpProgressMonitor __monitor;
		private final byte[] __handle;

		GetInputStream(long skip, byte[] handle, SftpProgressMonitor monitor) {
			__offset = skip;
			__monitor = monitor;
			__handle = handle;
		}

		@Override
		public int read() throws IOException {
			int i = read(__data, 0, 1);	// Read in one byte
			return i == -1 ? -1 : __data[0] & 0xff;
		}

		@Override
		public int read(byte[] b) throws IOException {
			return read(b, 0, b.length);
		}

		@Override
		public int read(byte[] b, int s, int len) throws IOException {
			if( __closed ) {
				return -1;
			} else if( len == 0 ) {
				return 0;
			}

			if( __restLength > 0 ) {
				int readLen = __restLength > len ? len : __restLength;
				System.arraycopy(__restByte, 0, b, s, readLen);
				if( readLen != __restLength ) {
					System.arraycopy(__restByte, readLen, __restByte, 0, __restLength - readLen);
				}

				if( __monitor != null && !__monitor.count(readLen) ) {
					close();
					return -1;
				}
				__restLength -= readLen;
				return readLen;
			}

			if( _buffer.buffer.length - 13 < len ) {
				len = _buffer.buffer.length - 13;
			}
			if( _serverVersion == 0 && len > 1024 ) {
				len = 1024;
			}

			try {
				sendREAD(__handle, __offset, len);
			} catch(Exception e) {
				throw new IOException("Failed to send read request", e);
			}
			readHeader();
			__restLength = _header.length;

			if( _header.type != SSH_FXP_STATUS && _header.type != SSH_FXP_DATA ) {
				throw new IOException("Invalid status response: "+_header.type);
			} else if( _header.type == SSH_FXP_STATUS ) {
				fill(_buffer, __restLength);
				int i = _buffer.getInt();
				__restLength = 0;
				if( i == SSH_FX_EOF ) {
					close();
					return -1;
				}
				throw new IOException("Invalid status response: "+i);
			}
			_buffer.rewind();
			fill(_buffer.buffer, 0, 4);
			int i, availableLen = _buffer.getInt();	// Available length returned
			__restLength -= 4;

			__offset += __restLength;
			if( availableLen > 0 ) {
				int readLen = __restLength > len ? len : __restLength;
				i = _io_in.read(b, s, readLen);
				if( i < 0 ) {
					return -1;
				}
				__restLength -= i;

				if( __restLength > 0 ) {
					if( __restByte.length < __restLength ) {
						__restByte = new byte[__restLength];
					}
					int j, _s = 0, _len = __restLength;
					while( _len > 0 ) {
						if( (j = _io_in.read(__restByte, _s, _len)) <= 0 ) {
							break;
						}
						_s += j;
						_len -= j;
					}
				}

				if( __monitor != null && !__monitor.count(i) ) {
					close();
					return -1;
				}
				return i;
			}
			return 0; // ??
		}

		@Override
		public void close() throws IOException {
			if( __closed ) {
				return;
			}
			__closed = true;
			if( __monitor != null ) {
				__monitor.end();
			}
			try {
				_sendCLOSE(__handle);
			} catch(Exception e) {
				throw new IOException("Failed to close InputStream", e);
			}
		}
	}

}
