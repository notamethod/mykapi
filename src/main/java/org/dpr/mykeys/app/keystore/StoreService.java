package org.dpr.mykeys.app.keystore;


import java.util.List;

import org.dpr.mykeys.app.certificate.MkCertificate;
import org.dpr.mykeys.app.common.NodeInfo;
import org.dpr.mykeys.app.utils.ServiceException;

public  interface StoreService<T extends NodeInfo> {

	 
	List<? extends MkCertificate> getChildList() throws ServiceException;
	

}