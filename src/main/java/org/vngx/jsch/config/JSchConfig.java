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

package org.vngx.jsch.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.vngx.jsch.Util;
import org.vngx.jsch.algorithm.Algorithms;
import org.vngx.jsch.algorithm.Compression;
import org.vngx.jsch.userauth.GSSContextKrb5;
import org.vngx.jsch.userauth.UserAuthGSSAPIWithMIC;
import org.vngx.jsch.userauth.UserAuthKeyboardInteractive;
import org.vngx.jsch.userauth.UserAuthNone;
import org.vngx.jsch.userauth.UserAuthPassword;
import org.vngx.jsch.userauth.UserAuthPublicKey;

/**
 * <p>{@code JSchConfig} is a singleton of a global configuration for setting
 * and retrieving vngx-jsch library configuration properties.  The configuration
 * defines all the properties which can be set and defines the validators to
 * ensure property values are valid.</p>
 *
 * <p>In addition, {@code JSchConfig} serves as the parent configuration for all
 * {@code SessionConfig} instances, ensuring that any properties not overloaded
 * by the individual session configuration instances use the default global
 * property values.</p>
 *
 * <p><strong>Note:</strong> This implementation is synchronized and thread-safe.</p>
 *
 * @author Michael Laudati
 */
public class JSchConfig implements SSHConfigConstants {

	/** Singleton instance of global JSch configuration. */
	private final static JSchConfig INSTANCE = new JSchConfig();

	/** 
	 * Stores the default property values for configuration properties.  Any
	 * requested property value not found in the global instance will attempt
	 * to retrieve the value from the default property map.
	 */
	private static final ConcurrentMap<String,String> DEFAULTS = new ConcurrentHashMap<String,String>();
	/** 
	 * Property validators mapped by property name to provide validation of
	 * property values when being set by user/program.  Validators also provide
	 * a default property value which is returned if no value is defined in the
	 * defaults map or in the global instance map.
	 */
	private static final ConcurrentMap<String,PropertyValidator> VALIDATORS = new ConcurrentHashMap<String,PropertyValidator>();

	/**
	 * Static initialization of default global JSch configuration properties
	 * along with their respective validators. For properties which map to real
	 * class implementations, it's better to retrieve the class name from the
	 * imported class reference for better maintainability: if a class is
	 * renamed or removed it will be reflected immediately during compilation.
	 */
	static {
		// Set the default global configuration values
		VALIDATORS.put(STRICT_HOST_KEY_CHECKING, new StringSetPropertyValidator("ask", "ask", "yes", "no"));
		VALIDATORS.put(HASH_KNOWN_HOSTS, BooleanPropertyValidator.DEFAULT_FALSE_VALIDATOR);
		VALIDATORS.put(COMPRESSION_LEVEL, NumberPropertyValidator.createValidator(0, 9, 6));

		// Set the defaults for key exchange proposals
		DEFAULTS.put(KEX_ALGORITHMS, "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1");
		DEFAULTS.put(KEX_SERVER_HOST_KEY, "ssh-rsa,ssh-dss");
		DEFAULTS.put(KEX_CIPHER_S2C, "aes128-ctr,3des-ctr,blowfish-cbc,aes192-cbc,aes256-cbc,aes128-cbc,3des-cbc");
		DEFAULTS.put(KEX_CIPHER_C2S, "aes128-ctr,3des-ctr,blowfish-cbc,aes192-cbc,aes256-cbc,aes128-cbc,3des-cbc");
		DEFAULTS.put(KEX_MAC_S2C, "hmac-sha256,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96");
		DEFAULTS.put(KEX_MAC_C2S, "hmac-sha256,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96");
		DEFAULTS.put(KEX_COMPRESSION_S2C, Compression.COMPRESSION_NONE);
		DEFAULTS.put(KEX_COMPRESSION_C2S, Compression.COMPRESSION_NONE);
		DEFAULTS.put(KEX_LANG_S2C, EMPTY);
		DEFAULTS.put(KEX_LANG_C2S, EMPTY);

		// Set the default security provider (empty to default to JCE default)
		DEFAULTS.put(DEFAULT_SECURITY_PROVIDER, EMPTY);

		DEFAULTS.put(HASH_KNOWN_HOSTS, "no");
		DEFAULTS.put(PREFFERED_AUTHS, "gssapi-with-mic,publickey,keyboard-interactive,password");

		// Load defaults/validators User Auth implementations
		VALIDATORS.put(Algorithms.USERAUTH_NONE, new PropertyValidator(UserAuthNone.class.getName()));
		VALIDATORS.put(Algorithms.USERAUTH_PASSWORD, new PropertyValidator(UserAuthPassword.class.getName()));
		VALIDATORS.put(Algorithms.USERAUTH_KB_INTERACTIVE, new PropertyValidator(UserAuthKeyboardInteractive.class.getName()));
		VALIDATORS.put(Algorithms.USERAUTH_PUBLICKEY, new PropertyValidator(UserAuthPublicKey.class.getName()));
		VALIDATORS.put(Algorithms.USERAUTH_GSSAPI_MIC, new PropertyValidator(UserAuthGSSAPIWithMIC.class.getName()));
		VALIDATORS.put(Algorithms.GSSAPI_WITH_MIC_KRB5, new PropertyValidator(GSSContextKrb5.class.getName()));
	}

	/**
	 * Parent configuration to search for property value when the value is not
	 * found in this instance.  The global singleton configuration instance must
	 * have a null parent.
	 */
	private final JSchConfig _parentConfig;
	/** Stores the properties of this configuration as name, value pairs. */
	private final ConcurrentMap<String,String> _props = new ConcurrentHashMap<String,String>();


	/**
	 * Private constructor to prevent direct instantiation of global singleton.
	 */
	private JSchConfig() {
		_parentConfig = null;	// Root does not have parent configuration
	}

	/**
	 * Package constructor to create new instance for {@code SessionConfig}
	 * which can specify a parent configuration or by default uses the default
	 * global configuration as the parent.
	 *
	 * @param parentConfig
	 */
	JSchConfig(SessionConfig parentConfig) {
		_parentConfig = parentConfig != null ? parentConfig : INSTANCE;
	}

	/**
	 * Returns the singleton instance of {@code JSchConfig}.
	 *
	 * @return singleton instance of global configuration
	 */
	public static JSchConfig getConfig() {
		return INSTANCE;
	}

	/**
	 * Creates a new instance of the specified configuration property.
	 *
	 * @param <T> type of class
	 * @param implClass property name (value retrieved from configuration)
	 * @return new instance of class
	 * @throws Exception if any errors occur
	 */
	@SuppressWarnings("unchecked")
	public final <T> T getClassImpl(String implClass) throws Exception {
		return (T) Class.forName(getString(implClass)).newInstance();
	}

	/**
	 * Returns a {@code NavigableSet} of all the property names defined in the
	 * configuration.
	 *
	 * @return property names defined in configuration
	 */
	public final NavigableSet<String> getPropertyNames() {
		NavigableSet<String> properties = new TreeSet<String>();
		properties.addAll(DEFAULTS.keySet());	// Add any properties in defaults
		properties.addAll(VALIDATORS.keySet());	// Add any properties in validators
		return properties;
	}

	/**
	 * Returns a {@code NavigableSet} of all property names which are explicitly
	 * set/defined in this configuration instance.  This will exclude default
	 * property names and property names defined in parent instances.
	 *
	 * @return defined property name set
	 */
	public final NavigableSet<String> getDefinedPropertyNames() {
		return new TreeSet<String>(_props.keySet());
	}

	/**
	 * Returns the String value for the specified property or empty by default.
	 *
	 * @param property name
	 * @return String value of property
	 */
	public final String getString(String property) {
		return getString(property, EMPTY);
	}

	/**
	 * Returns the property value for the specified property name.  First
	 * searches this instance's local property store, then searches the parent
	 * configuration if it exists, then searches the default properties and
	 * lastly the property validators.  If a value still cannot be found, then
	 * the alternate string is returned.
	 *
	 * @param property
	 * @param alternate
	 * @return property value or alternate for no match
	 */
	private String getString(String property, String alternate) {
		if( _props.containsKey(property) ) {
			return _props.get(property);
		} else if( _parentConfig != null ) {
			return _parentConfig.getString(property, alternate);
		} else if( DEFAULTS.containsKey(property) ) {
			return DEFAULTS.get(property);
		} else if( VALIDATORS.containsKey(property) ) {
			return VALIDATORS.get(property).getDefaultValue();
		}
		return alternate;
	}

	/**
	 * Returns the boolean value for the specified property or false by default.
	 *
	 * @param property name
	 * @return boolean value of property
	 */
	public final boolean getBoolean(String property) {
		return getBoolean(property, false);
	}
	
	private boolean getBoolean(String property, boolean alternate) {
		String retValue = getString(property, null);
		return retValue != null ? Boolean.parseBoolean(retValue) : alternate;
	}

	/**
	 * Returns the integer value for the specified property or zero by default.
	 * 
	 * @param property name
	 * @return integer value of property
	 */
	public final int getInteger(String property) {
		return getInteger(property, 0);
	}

	private int getInteger(String property, int alternate) {
		String retValue = getString(property, null);
		return retValue != null ? Integer.parseInt(retValue) : alternate;
	}

	/**
	 * Returns a list of Strings parsed from the comma delimited property value.
	 *
	 * @param property name
	 * @return list of Strings parsed from comma delimited property value
	 */
	@SuppressWarnings("unchecked")
	public final List<String> getList(String property) {
		String retValue = getString(property, null);
		return (List<String>) (retValue != null ? Arrays.asList(retValue.split(",")) : Collections.emptyList());
	}

	/**
	 * Returns true if the specified property and value are valid.
	 *
	 * @param property name
	 * @param value of property
	 * @return true if property and value are valid (can be set in configuration)
	 */
	public final boolean isPropertyValid(String property, String value) {
		return VALIDATORS.containsKey(property) ? VALIDATORS.get(property).isPropertyValid(value) : value != null;
	}

	/**
	 * Sets the specified property value in the configuration.  If an invalid
	 * property name or value is set, an {@code InvalidPropertyException}
	 * will be thrown.
	 *
	 * @param property name
	 * @param value of property
	 * @throw InvalidPropertyException if invalid property is set
	 */
	public final void setProperty(String property, String value) {
		if( property == null || property.length() == 0 ){
			throw new InvalidPropertyException(property, value, "Property name cannot be null/empty");
		} else if( !isPropertyValid(property, value) ) {
			throw new InvalidPropertyException(property, value);
		}
		_props.put(property, value);
	}

	/**
	 * Sets the specified property value in the configuration.  If an invalid
	 * property name or value is set, an {@code InvalidPropertyException}
	 * will be thrown.
	 *
	 * @param property name
	 * @param value of property
	 * @throw InvalidPropertyException if invalid property is set
	 */
	public final void setProperty(String property, boolean value) {
		setProperty(property, String.valueOf(value));
	}

	/**
	 * Sets the specified property value in the configuration.  If an invalid
	 * property name or value is set, an {@code InvalidPropertyException}
	 * will be thrown.
	 *
	 * @param property name
	 * @param value of property
	 * @throw InvalidPropertyException if invalid property is set
	 */
	public final void setProperty(String property, int value) {
		setProperty(property, String.valueOf(value));
	}

	/**
	 * Sets the specified property value in the configuration.  If an invalid
	 * property name or value is set, an {@code InvalidPropertyException}
	 * will be thrown.
	 *
	 * @param property name
	 * @param list of Strings to join as property (element1,element2,element3,etc)
	 * @throw InvalidPropertyException if invalid property is set
	 */
	public final void setProperty(String property, List<String> list) {
		setProperty(property, Util.join(list, ","));
	}

	final void validateProperties() throws InvalidPropertyException {
		for( Map.Entry<String,PropertyValidator> entry : VALIDATORS.entrySet() ) {
			if( !entry.getValue().isPropertyValid(getString(entry.getKey())) ) {
				throw new InvalidPropertyException(entry.getKey(), getString(entry.getKey()));
			}
		}
	}

}
