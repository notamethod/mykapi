package com.notamethod.mkcore.certificate.profile;

public class ProfilException extends Exception {

	public ProfilException(String string) {
		super(string);
		// TODO Auto-generated constructor stub
	}

    public ProfilException(String string, Exception e)
    {
       super(string, e);
    }

}
