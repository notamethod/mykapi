package org.dpr.mykeys.app.keystore;

import org.dpr.mykeys.app.utils.ServiceException;

public class PasswordNotFoundException extends ServiceException {

	public PasswordNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	public PasswordNotFoundException(Throwable cause) {
		super(cause);
	}

	public PasswordNotFoundException(String s) {
		super(s);
	}
}
