package com.notamethod.mkcore.keystore;


import java.util.List;

import com.notamethod.mkcore.certificate.MkCertificate;
import com.notamethod.mkcore.common.NodeInfo;
import com.notamethod.mkcore.utils.ServiceException;

public  interface StoreService<T extends NodeInfo> {

	 
	List<? extends MkCertificate> getChildList() throws ServiceException;
	

}