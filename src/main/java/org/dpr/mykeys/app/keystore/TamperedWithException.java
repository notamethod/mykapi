package org.dpr.mykeys.app.keystore;

import org.dpr.mykeys.app.KeyToolsException;
import org.dpr.mykeys.app.ServiceException;

public class TamperedWithException extends Exception {

	public TamperedWithException(Exception e) {
		super (e);
	}


}
