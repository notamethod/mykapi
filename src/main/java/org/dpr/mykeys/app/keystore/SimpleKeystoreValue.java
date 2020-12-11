package org.dpr.mykeys.app.keystore;

import org.dpr.mykeys.app.certificate.Certificate;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SimpleKeystoreValue implements MKKeystoreValue {
    private final List<Certificate> certificates = new ArrayList<>();
    private final List<Object> elements = new ArrayList<>();
    protected String path;
    protected StoreFormat storeFormat;
    private boolean isLoaded = false;

    public StoreFormat getStoreFormat() {
        return storeFormat;
    }

    public void setStoreFormat(StoreFormat storeFormat) {
        this.storeFormat = storeFormat;
    }

    public SimpleKeystoreValue(String path, StoreFormat format) {
        this.path = new File(path).getPath();
        this.storeFormat = format;
    }

    @Override
    public boolean isLoaded() {
        return isLoaded;
    }

    public void setLoaded(boolean loaded) {
        isLoaded = loaded;
    }
    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public List<Certificate> getCertificates() {
        return certificates;
    }

    @Override
    public void setCertificates(List<Certificate> certificates) {
        this.certificates.clear();
        this.certificates.addAll(certificates);
    }

    public void addElement(Object object){
        elements.add(object);
    }
    public void addAllElements(List<Object> elements){

        this.elements.addAll(elements);
    }

    public List<Object>  getElements(){
        return elements;
    }
}
