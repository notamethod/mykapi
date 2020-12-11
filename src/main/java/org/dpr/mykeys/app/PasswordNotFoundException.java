package org.dpr.mykeys.app;

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
