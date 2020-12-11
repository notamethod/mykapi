package org.dpr.mykeys.app.keystore;


import java.util.List;

import org.dpr.mykeys.app.certificate.MkCertificate;
import org.dpr.mykeys.app.NodeInfo;
import org.dpr.mykeys.app.ServiceException;

public  interface StoreService<T extends NodeInfo> {

	 
	List<? extends MkCertificate> getChildList() throws ServiceException;
	

}