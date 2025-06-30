/**
 * 
 */
package com.notamethod.mkcore.common;

import com.notamethod.mkcore.certificate.MkCertificate;

import java.util.List;

/**
 * @author Buck
 *
 */
public interface NodeInfo {

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
    String toString();

	/**
	 * @return the name
	 */
    String getName();

	/**
	 * @param name
	 *            the name to set
	 */
    void setName(String name);

	/**
	 * @return the path
	 */
    String getPath();

	/**
	 * @param path
	 *            the path to set
	 */
    void setPath(String path);

	/**
	 * @return the isOpen
	 */
    boolean isOpen();

	/**
	 * @param isOpen
	 *            the isOpen to set
	 */
    void setOpen(boolean isOpen);


    List<? extends MkCertificate> getChildList();

    boolean isProtected();

    void open();



}
