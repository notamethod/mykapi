/**
 *
 */
package com.notamethod.mkcore.crl;

import com.notamethod.mkcore.certificate.MkCertificate;
import com.notamethod.mkcore.common.NodeInfo;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;


/**
 * @author Buck
 */
public class CrlValue implements NodeInfo {
    private Date thisUpdate = new Date();
    private Date nextUpdate;
    private String name;
    private String path;

    private BigInteger number = BigInteger.ONE;

    /**
     * Retourne le thisUpdate.
     *
     * @return Date - le thisUpdate.
     */
    public Date getThisUpdate() {
        return thisUpdate;
    }

    /**
     * Affecte le thisUpdate.
     *
     * @param thisUpdate le thisUpdate à affecter.
     */
    public void setThisUpdate(Date thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    /**
     * Retourne le nextUpdate.
     *
     * @return Date - le nextUpdate.
     */
    public Date getNextUpdate() {
        return nextUpdate;
    }

    /**
     * Affecte le nextUpdate.
     *
     * @param nextUpdate le nextUpdate à affecter.
     */
    public void setNextUpdate(Date nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    /**
     * Retourne le number.
     *
     * @return BigInteger - le number.
     */
    public BigInteger getNumber() {
        return number;
    }

    /**
     * Affecte le number.
     *
     * @param number le number à affecter.
     */
    public void setNumber(BigInteger number) {
        this.number = number;
    }

    /**
     * .
     * <p>
     * <BR>
     *
     * @return
     * @see NodeInfo#getName()
     */
    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return name;
    }

    /**
     * .
     * <p>
     * <BR>
     *
     * @return
     * @see NodeInfo#getPath()
     */
    @Override
    public String getPath() {
        // TODO Auto-generated method stub
        return path;
    }

    /**
     * .
     * <p>
     * <BR>
     *
     * @param name
     * @see NodeInfo#setName(java.lang.String)
     */
    @Override
    public void setName(String name) {
        this.name = name;

    }

    /**
     * .
     * <p>
     * <BR>
     *
     * @param path
     * @see NodeInfo#setPath(java.lang.String)
     */
    @Override
    public void setPath(String path) {
        this.path = path;

    }

    /**
     * .
     * <p>
     * <BR>
     *
     * @return
     * @see NodeInfo#isOpen()
     */
    @Override
    public boolean isOpen() {
        // TODO Auto-generated method stub
        return false;
    }

    /**
     * .
     * <p>
     * <BR>
     *
     * @param isOpen
     * @see NodeInfo#setOpen(boolean)
     */
    @Override
    public void setOpen(boolean isOpen) {
        // TODO Auto-generated method stub

    }

    @Override
    public List<? extends MkCertificate> getChildList() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isProtected() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void open() {
        // TODO Auto-generated method stub

    }

}
