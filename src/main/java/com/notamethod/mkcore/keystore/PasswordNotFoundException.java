package com.notamethod.mkcore.keystore;

import com.notamethod.mkcore.utils.ServiceException;

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
