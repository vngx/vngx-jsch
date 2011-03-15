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

import static org.vngx.jsch.constants.SftpProtocol.*;

import java.util.Date;

/**
 * Attribute information for a path as retrieved from the sftp session.
 *
 * @author Atsuhiko Yamanaka
 * @author Michael Laudati
 */
public final class SftpATTRS {

	/** Constant code for permissions mask. */
	private static final int PERMISSION_MASK = 0xFFF;

	/** Permission flags for file (stored per bit). */
	private int _flags = 0;
	/** Size in bytes of file. */
	private long _size;
	/** User ID of file. */
	private int _userId;
	/** Group ID of file. */
	private int _groupId;
	/** File permissions. */
	private int _permissions;
	/** Access timestamp (UN*X timestamp is only 32 bit, not long). */
	private int _accessTime;
	/** Modified timestamp (UN*X timestamp is only 32 bit, not long). */
	private int _modifiedTime;
	/** Extended data for file. */
	private String[] _extended;


	/**
	 * Creates a new instance of <code>SftpATTRS</code> from the specified
	 * <code>Buffer</code> response from the SFTP channel containing the
	 * file attributes.
	 *
	 * The buffer should have the following structure:
	 *
	 *	uint32   flags
	 *	uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
	 *	uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
	 *	uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
	 *	uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
	 *	uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
	 *	uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
	 *	uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
	 *	string   extended_type
	 *	string   extended_data
	 *	...      more extended data (extended_type - extended_data pairs),
	 *	so that number of pairs equals extended_count
	 *
	 * @see org.vngx.jsch.SftpATTRS#getATTR(com.jcraft.jsch.Buffer)
	 *
	 * @param buffer containing attribute information
	 */
	private SftpATTRS(Buffer buffer) {
		_flags = buffer.getInt();
		if( (_flags & SSH_FILEXFER_ATTR_SIZE) != 0 ) {
			_size = buffer.getLong();
		}
		if( (_flags & SSH_FILEXFER_ATTR_UIDGID) != 0 ) {
			_userId = buffer.getInt();
			_groupId = buffer.getInt();
		}
		if( (_flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 ) {
			_permissions = buffer.getInt();
		}
		if( (_flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 ) {
			_accessTime = buffer.getInt();
			_modifiedTime = buffer.getInt();
		}
		if( (_flags & SSH_FILEXFER_ATTR_EXTENDED) != 0 ) {
			int count = buffer.getInt();
			if( count > 0 ) {
				_extended = new String[count * 2];
				for( int i = 0; i < count; i++ ) {
					_extended[i * 2] = Util.byte2str(buffer.getString());
					_extended[i * 2 + 1] = Util.byte2str(buffer.getString());
				}
			}
		}
	}

	/**
	 * Creates a new instance of <code>SftpATTRS</code> from the specified
	 * <code>Buffer</code> response from the SFTP channel containing the
	 * file attributes.
	 *
	 * @param buffer containing attribute information
	 * @return SftpATTRS instance
	 */
	static SftpATTRS getATTR(Buffer buffer) {
		return new SftpATTRS(buffer);
	}

	/**
	 * Returns a descriptive permissions string similar to 'ls' output.
	 *
	 * @return permissions String
	 */
	public String getPermissionsString() {
		StringBuilder buffer = new StringBuilder(10);
		if( isDir() ) {
			buffer.append('d');
		} else if( isLink() ) {
			buffer.append('l');
		} else {
			buffer.append('-');
		}

		if( (_permissions & S_IRUSR) != 0 ) {
			buffer.append('r');
		} else {
			buffer.append('-');
		}
		if( (_permissions & S_IWUSR) != 0 ) {
			buffer.append('w');
		} else {
			buffer.append('-');
		}
		if( (_permissions & S_ISUID) != 0 ) {
			buffer.append('s');
		} else if( (_permissions & S_IXUSR) != 0 ) {
			buffer.append('x');
		} else {
			buffer.append('-');
		}

		if( (_permissions & S_IRGRP) != 0 ) {
			buffer.append('r');
		} else {
			buffer.append('-');
		}
		if( (_permissions & S_IWGRP) != 0 ) {
			buffer.append('w');
		} else {
			buffer.append('-');
		}
		if( (_permissions & S_ISGID) != 0 ) {
			buffer.append('s');
		} else if( (_permissions & S_IXGRP) != 0 ) {
			buffer.append('x');
		} else {
			buffer.append('-');
		}

		if( (_permissions & S_IROTH) != 0 ) {
			buffer.append('r');
		} else {
			buffer.append('-');
		}
		if( (_permissions & S_IWOTH) != 0 ) {
			buffer.append('w');
		} else {
			buffer.append('-');
		}
		if( (_permissions & S_IXOTH) != 0 ) {
			buffer.append('x');
		} else {
			buffer.append('-');
		}
		return buffer.toString();
	}

	/**
	 * Returns the length in bytes of the buffer required to hold the attribute
	 * information.
	 *
	 * @return length of attribute information
	 */
	int length() {
		int len = 4;
		if( (_flags & SSH_FILEXFER_ATTR_SIZE) != 0 ) {
			len += 8;
		}
		if( (_flags & SSH_FILEXFER_ATTR_UIDGID) != 0 ) {
			len += 8;
		}
		if( (_flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 ) {
			len += 4;
		}
		if( (_flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 ) {
			len += 8;
		}
		if( (_flags & SSH_FILEXFER_ATTR_EXTENDED) != 0 ) {
			len += 4;
			int count = _extended.length / 2;
			if( count > 0 ) {
				for( int i = 0; i < count; i++ ) {
					len += 4;
					len += _extended[i * 2].length();
					len += 4;
					len += _extended[i * 2 + 1].length();
				}
			}
		}
		return len;
	}

	/**
	 * Dumps the attribute information to the specified buffer instance.
	 *
	 * @param buffer to dump attribute information into
	 */
	void dump(Buffer buffer) {
		buffer.putInt(_flags);
		if( (_flags & SSH_FILEXFER_ATTR_SIZE) != 0 ) {
			buffer.putLong(_size);
		}
		if( (_flags & SSH_FILEXFER_ATTR_UIDGID) != 0 ) {
			buffer.putInt(_userId);
			buffer.putInt(_groupId);
		}
		if( (_flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 ) {
			buffer.putInt(_permissions);
		}
		if( (_flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 ) {
			buffer.putInt(_accessTime);
			buffer.putInt(_modifiedTime);
		}
		if( (_flags & SSH_FILEXFER_ATTR_EXTENDED) != 0 ) {
			int count = _extended.length / 2;
			if( count > 0 ) {
				for( int i = 0; i < count; i++ ) {
					buffer.putString(_extended[i * 2]);
					buffer.putString(_extended[i * 2 + 1]);
				}
			}
		}
	}

	/**
	 * Sets the flags for this attribute.
	 *
	 * @param flags
	 */
	void setFLAGS(int flags) {
		_flags = flags;
	}

	/**
	 * Sets the size in bytes for this attribute.
	 *
	 * @param size in bytes to set
	 */
	public void setSIZE(long size) {
		_flags |= SSH_FILEXFER_ATTR_SIZE;
		_size = size;
	}

	/**
	 * Sets the user ID and group ID for this attribute.
	 *
	 * @param uid user ID to set
	 * @param gid group ID to set
	 */
	public void setUIDGID(int uid, int gid) {
		_flags |= SSH_FILEXFER_ATTR_UIDGID;
		_userId = uid;
		_groupId = gid;
	}

	/**
	 * Sets the access and modified timestamps for this attribute.
	 *
	 * @param accessTime to set
	 * @param modifiedTime to set
	 */
	public void setACMODTIME(int accessTime, int modifiedTime) {
		_flags |= SSH_FILEXFER_ATTR_ACMODTIME;
		_accessTime = accessTime;
		_modifiedTime = modifiedTime;
	}

	/**
	 * Sets the permissions flags for this attribute.
	 *
	 * @param permissions
	 */
	public void setPERMISSIONS(int permissions) {
		_flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
		permissions = (_permissions & ~PERMISSION_MASK) | (permissions & PERMISSION_MASK);
		_permissions = permissions;
	}

	/**
	 * Returns true if the attribute represents a directory.
	 *
	 * @return true if attribute is a directory
	 */
	public boolean isDir() {
		return (_flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 &&
				((_permissions & S_IFDIR) == S_IFDIR);
	}

	/**
	 * Returns true if this attribute is a symbolic link.
	 *
	 * @return true if attribute is a symbolic link
	 */
	public boolean isLink() {
		return (_flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 &&
				((_permissions & S_IFLNK) == S_IFLNK);
	}

	/**
	 * Returns the flags indicating which attributes are represented in this
	 * instance.
	 *
	 * @return permission flags
	 */
	public int getFlags() {
		return _flags;
	}

	/**
	 * Returns the file size in bytes for the attribute.
	 * 
	 * @return file size in bytes
	 */
	public long getSize() {
		return _size;
	}

	/**
	 * Returns the user ID for the attribute.
	 *
	 * @return user ID
	 */
	public int getUId() {
		return _userId;
	}

	/**
	 * Returns the group ID for the attribute.
	 *
	 * @return group ID
	 */
	public int getGId() {
		return _groupId;
	}

	/**
	 * Returns the permissions for this attribute.
	 *
	 * @return permissions
	 */
	public int getPermissions() {
		return _permissions;
	}

	/**
	 * Returns the access timestamp for this attribute.
	 *
	 * @return access timestamp
	 */
	public int getAccessTime() {
		return _accessTime;
	}

	/**
	 * Returns the modified timestamp for this attribute.
	 *
	 * @return modified timestamp
	 */
	public int getModifiedTime() {
		return _modifiedTime;
	}

	/**
	 * Returns the extended information about this attribute.
	 *
	 * @return extended information
	 */
	public String[] getExtended() {
		return _extended;
	}

	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder(200);
		buffer.append(getPermissionsString()).append(' ');
		buffer.append(_userId).append(' ');
		buffer.append(_groupId).append(' ');
		buffer.append(_size).append(' ');
		buffer.append(new Date(((long) _modifiedTime) * 1000));
		return buffer.toString();
	}

}
