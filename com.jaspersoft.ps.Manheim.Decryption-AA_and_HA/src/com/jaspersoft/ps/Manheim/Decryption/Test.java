package com.jaspersoft.ps.Manheim.Decryption;

import static org.junit.Assert.*;


public class Test {

	@org.junit.Test
	public void test() {
		Cypher c = new Cypher();
		
		if(!c.isTokenStillValid("2015-08-06T16:02:09Z"))
		{
			fail();
		}
		
		
	}
}
