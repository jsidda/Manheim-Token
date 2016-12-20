package com.jaspersoft.ps.Manheim.Decryption;

import java.io.IOException;
import java.sql.Connection;

import com.jaspersoft.jasperserver.api.common.crypto.CipherI;
import com.manheim.security.jaspersoft.ReportingCryptoUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;



//*****
//** note: Client has decided to use 256 encryption which requires new security JARs.
//**http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
//**the above link is needed to get the right security files for your Java install.
//***
public class Cypher implements CipherI
{
	@Override
	public String encrypt(String plainText) {
		return plainText;
	}

//	private static Log log = LogFactory.getLog(Cypher.class);
	private static Logger log = Logger.getLogger("MyLog");  
	private static FileHandler fh; 
	private String enablelogging;
	private String logginglocation;
	private boolean shouldlog = false;
	private String EBS;
	private String ODS;
	private String monitorusername;
	private String roleformonitoruser;
	
	@Override
	public String decrypt(String cipherText) {
	
		if (enablelogging.equals("true"))
		{
			shouldlog = true;
		 try {
			 fh = new FileHandler(logginglocation);
		} catch (SecurityException | IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}  
	        log.addHandler(fh);
	        SimpleFormatter formatter = new SimpleFormatter();  
	        fh.setFormatter(formatter);  
		}
		    
	    //as of 20150605 the token expression is expect to be:
		//pp=u=employeeid|t=e|r=|o=|e=20150605230000
		// pp=u=100000123|t=c|r=|o=|e=20150605230000
		//**this code was for testing only and is removed as of 7/9/2015
		/*
		if (cipherText.contains("u=emp"))
		{
			if(shouldlog){log.info("u=emp was found. Using FAKE employee token...");}
			try {
				cipherText = ReportingCryptoUtils.encryptEmployeeToken("TCAREY", "Tara Carey", false);
				//System.out.println(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		if (cipherText.contains("u=yfake"))
		{
			if(shouldlog){log.info("u=emp was found. Using FAKE employee token that does not exist in db...");}
			try {
				cipherText = ReportingCryptoUtils.encryptEmployeeToken("EMPFAKE", "Does Not Exist", false);
				//System.out.println(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		if (cipherText.contains("u=cus"))
		{
			if(shouldlog){log.info("u=cus was found. Using FAKE user token....");}
			try {
				cipherText = ReportingCryptoUtils.encryptCustomerToken("thomassubaru", "thomassubaru", true);
				System.out.println(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		if (cipherText.contains("u=z"))
		{
			if(shouldlog){log.info("u=cusemp was found. Using FAKE useremp token....");}
			try {
				cipherText = ReportingCryptoUtils.encryptEmployeeAsCustomerToken("TCAREY", "Tara Carey", "100549048", true);
				System.out.println(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		if (cipherText.contains("u=" + monitorusername))
		{
			if(shouldlog){log.info("u=jaspermonitor was found. Using FAKE jaspermonitor token....");}
			try {
				cipherText = ReportingCryptoUtils.encryptCustomerToken(monitorusername, monitorusername, true);
				System.out.println(cipherText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		*/
		//cipherText = "Mt7GaVmZzBUEcvI6m04BVzQTiC5jAxESN8sFG9bHf79hRiTiNHILR7yN9-pRbRBYUmTOKwjT6ZJKfggKhi4PKT6QeV8SSJgf";
		
		String token = "";
		try {
			if(shouldlog){log.info("Decrypting token..");}
			cipherText = ReportingCryptoUtils.decryptToken(cipherText);
			if(shouldlog){log.info("token decrypted.");}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			if(shouldlog){log.info("error decrypting token: " + e.getMessage());}
		} 
		System.out.println(GetItemFromToken(cipherText,"u").contains(monitorusername));
		//we need to see if this is the special monitoring user
		if(GetItemFromToken(cipherText,"u").contains(monitorusername))
		{
			 token = "u=" + monitorusername + "|";
			 token += "o=organization_1|";
			 token += "r=" + roleformonitoruser;
	    	 if(shouldlog){log.info("Token being passed to actually login is: " + token);}
	    	 return token;
		}

		//check the date on the token
		if(isTokenStillValid(GetItemFromToken(cipherText,"e")) == true)
		{
			if(shouldlog){log.info("Token timestamp passed.");}
			
			if (cipherText.contains("t=ec"))
		     {
		    	 if(shouldlog){log.info("Token is for Employee as Customer.");}
		    	 //call get token for customer
		    	 token = GetTokenforEmployeeasCustomer(GetItemFromToken(cipherText,"u"),GetItemFromToken(cipherText,"dn"), GetItemFromToken(cipherText,"d"), cipherText);
		    	 if(shouldlog){log.info("Token being passed to actually login is: " + token);}
		    } else if(cipherText.contains("t=e"))
		     {
				if(shouldlog){log.info("Token is for Employee");}
				 //call get token for customer
		    	 token = GetTokenforEmployee(GetItemFromToken(cipherText,"u"), GetItemFromToken(cipherText,"dn"), GetItemFromToken(cipherText,"d"), cipherText);
		    	 if(shouldlog){log.info("Token being passed to actually login is: " + token);}
		     }
		     else if (cipherText.contains("t=c"))
		     {
		    	 if(shouldlog){log.info("Token is for Customer.");}
		    	 //call get token for customer
		    	 token = GetTokenforCustomer(GetItemFromToken(cipherText,"u"),GetItemFromToken(cipherText,"dn"), GetItemFromToken(cipherText,"d"), cipherText);
		    	 if(shouldlog){log.info("Token being passed to actually login is: " + token);}
		    } 
	  		return token;
		}
		else
		{
			if(shouldlog){log.info("Token timestamp failed! This is what I see:" + GetItemFromToken(cipherText,"e") );}
			return "";
		}
	}
	
	public boolean isTokenStillValid(String sExp) {
		java.text.DateFormat df = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    	df.setTimeZone(java.util.TimeZone.getTimeZone("Zulu"));
 
		@SuppressWarnings("deprecation")
		java.util.Date date = new java.util.Date("01/01/2015");
		try {
			date = df.parse(sExp);
	    	 if(shouldlog){log.info("Token exp date is: " + date.toString());}
		} catch (ParseException e) {
			// TODO Auto-generated catch block
	    	 if(shouldlog){log.info("Something went wrong when trying to find token exp date:" + sExp);}
			e.printStackTrace();
		}
    	
    	java.util.Date now = new java.util.Date();
    	
    	
    	long t = date.getTime();
    	date = new java.util.Date(t + (5*1000));
   	 	if(shouldlog){log.info("Comparison date is: " + now.toString() + " Source Date is : " + date.toString());}

   	 return true;
    //	return now.before(date);
	}

	private String GetTokenforCustomer(String custId, String FullName, String n100M, String oldToken)
	{
		Context ctx;
		String newToken = "";
		try {
			ctx = new InitialContext();
			//start of the db stuff.
			
		//	if(shouldlog){log.info(d.toString() +  "<- START the db stuff for this login");}
			
			DataSource ds = (DataSource) ctx.lookup("java:/comp/env/jdbc/ods");
		     
		     String SQL = "SELECT USERNAME FROM XODSADM.RTR_USER_REP_ACCOUNT_ROLE AR WHERE AR.ACTIVE_STATUS = 1 And Ar.Ods_Customer_Id Is Not Null And username = '%s'";
		     SQL = String.format(SQL,custId);
		   try(  Connection conn = ds.getConnection();
		     PreparedStatement statement = conn.prepareStatement(SQL); 
		     ResultSet result = statement.executeQuery(SQL)){
			Date e = new Date();
			if(shouldlog){log.info(e.toString() +  "<- END the db stuff for this login");}
		     if(shouldlog){log.info("SQL to get customer from db is: " + SQL);}
		     Boolean first = true;
		     while(result.next())
		     {
		    	 if(first)
		    	 {
		    		 first = false;
			    	 newToken = "u=" + result.getString("username") + "|";
			    	 newToken += "o=organization_1|";
			    	 newToken += "r=JRS_Customer|";
			    	 newToken += "pa1=" + n100M + "|";
			    	 newToken += "pa3=" + FullName + "|";
			    	 newToken += "pa4='C'|";
			    	 newToken += "pa5=AR.USERNAME|";
			    	 newToken += "pa6='" + custId + "'|";
			    	 newToken += "pa7=" + custId + "|";
			    	// newToken += "pa8=" + GetItemFromToken(oldToken,"aa") + "|";
			    	// newToken += "pa9=" + GetItemFromToken(oldToken,"ha") + "|";
			    	 
		    	 }
		     }  
		   }
		} catch (NamingException e) {
			// TODO Auto-generated catch block
	    	 if(shouldlog){log.info("Was trying to get user details from db. Error occurred: " + e.getMessage());}
			e.printStackTrace();
		} catch (SQLException e) {
	    	 if(shouldlog){log.info("Was trying to get user details from db. Error occurred: " + e.getMessage());}
	    	 // TODO Auto-generated catch block
			e.printStackTrace();
		}
   	 if(shouldlog){log.info("Token was created for Customer without error");}    
		return newToken;
	}
	private String GetTokenforEmployeeasCustomer(String custId, String FullName, String n100M, String oldToken)
	{
		Context ctx;
		String newToken = "";
		try {
			ctx = new InitialContext();
			Date d = new Date();
			if(shouldlog){log.info(d.toString() +  "<- START the db stuff for this login");}
			DataSource ds = (DataSource) ctx.lookup("java:/comp/env/jdbc/ods");
		     
		     String SQL = "SELECT USERNAME FROM XODSADM.RTR_USER_REP_ACCOUNT_ROLE AR WHERE AR.ACTIVE_STATUS = 1 And Ar.Ods_Customer_Id Is Not Null And rep_number= '%s'";
		     SQL = String.format(SQL,n100M);
		     try(Connection conn = ds.getConnection();
		     PreparedStatement statement = conn.prepareStatement(SQL); 
		     ResultSet result = statement.executeQuery(SQL)){
				Date e = new Date();
				if(shouldlog){log.info(e.toString() +  "<- END the db stuff for this login");}
	    	 if(shouldlog){log.info("SQL to get customer from db is: " + SQL);}
		     Boolean first = true;
		     while(result.next())
		     {
		    	 if(first)
		    	 {
		    		 first = false;
			    	 newToken = "u=" + custId + "|";
			    	 newToken += "o=organization_1|";
			    	 newToken += "r=JRS_EMP_CUSTOMER|";
			    	 newToken += "pa1=" + n100M + "|";
			    	 newToken += "pa3=" + FullName + "|";
			    	 newToken += "pa4='EC'|";
			    	 newToken += "pa5=AR.REP_NUMBER|";
			    	 newToken += "pa6='" + n100M + "'|";
			    	 newToken += "pa7=" + custId + "|";
			    	 newToken += "pa8=" + GetItemFromToken(oldToken,"aa") + "|";
			    	 newToken += "pa9=" + GetItemFromToken(oldToken,"ha") + "|";
			    	 
		    	 }
		     }
		     }
		} catch (NamingException e) {
			// TODO Auto-generated catch block
	    	 if(shouldlog){log.info("Was trying to get user details from db. Error occurred: " + e.getMessage());}
			e.printStackTrace();
		} catch (SQLException e) {
	    	 if(shouldlog){log.info("Was trying to get user details from db. Error occurred: " + e.getMessage());}
	    	 // TODO Auto-generated catch block
			e.printStackTrace();
		}
   	 if(shouldlog){log.info("Token was created for Customer without error"); }   
		return newToken;
	}
	private String GetTokenforEmployee(String custId, String FullName, String n100M, String oldToken)
	{
		Context ctx;
		String newToken = "";
		try {
			ctx = new InitialContext();
			Date d = new Date();
			if(shouldlog){log.info(d.toString() +  "<- START the db stuff for this login");}
			DataSource ds = (DataSource) ctx.lookup("java:/comp/env/jdbc/ebs");
		    
		     String SQL = "SELECT CASE WHEN SYSDATE BETWEEN NVL (usr.start_date, SYSDATE - 1) AND NVL (usr.end_date, SYSDATE + 1)  AND SYSDATE BETWEEN NVL (resp.start_date, SYSDATE - 1) AND NVL (resp.end_date, SYSDATE + 1)   AND SYSDATE BETWEEN NVL (userresp.start_date, SYSDATE - 1) AND NVL (userresp.end_date, SYSDATE + 1)   THEN 'Y'    ELSE      'N'  END   active_flag,    usr.user_name,   NVL (person.full_name, usr.description) full_name,   (SELECT person_type.user_person_type      FROM hr.per_person_types person_type     WHERE person_type.person_type_id = person.person_type_id)      person_type,   person.employee_number,     NVL (usr.email_address, person.email_address) email_address,     usr.start_date user_start_date,   usr.end_date user_end_date,      app.application_name,   resp.responsibility_name,   resp.description resp_description,   resp.start_date resp_start_date,   resp.end_date resp_end_date,   userresp.start_date userresp_start_date,   userresp.end_date userresp_end_date        FROM apps.fnd_user_resp_groups_all userresp,   applsys.fnd_user usr,   apps.fnd_application_vl app,   apps.fnd_responsibility_vl resp,   Hr.Per_All_People_F Person    Where  userresp.user_id = usr.user_id   AND userresp.responsibility_application_id = app.application_id   AND userresp.responsibility_application_id = resp.application_id   AND userresp.responsibility_id = resp.responsibility_id   AND usr.employee_id = person.person_id(+)   And Trunc (Sysdate) Between Person.Effective_Start_Date(+)   AND Person.Effective_End_Date(+)   And User_Name=UPPER('%s')    order by active_flag, resp.responsibility_name";
		     SQL = String.format(SQL,custId);
		    try( Connection conn = ds.getConnection();
		     PreparedStatement statement = conn.prepareStatement(SQL);
		     ResultSet result = statement.executeQuery(SQL)){
	    	 if(shouldlog){log.info("SQL to get employee from db is: " + SQL);}
		    
		     Date e = new Date();
		     if(shouldlog){log.info(e.toString() +  "<- END the db stuff for this login");}
		     Boolean first = true;
		     
		     //did the SQL return a value at all?		     
		     if (!result.isBeforeFirst() ) {  
		    	 //the user was not sent in. We trust the token, but only as a lower level user.
		    	 newToken = "u=" + custId + "|";
		    	 newToken += "o=organization_1|";
		    	 newToken += "r=JRS_LimitedAccess|";
		    	 newToken += "pa1=" + n100M + "|";
		    	 newToken += "pa2=" + custId + "|";
		    	 newToken += "pa3=" + FullName + "|";
		    	 newToken += "pa4='E'|";
		    	 newToken += "pa5=1|";
		    	 newToken += "pa6=1|";
		    	 newToken += "pa7=" + custId + "|";
		    	 newToken += "pa8=" + GetItemFromToken(oldToken,"aa") + "|";
		    	 newToken += "pa9=" + GetItemFromToken(oldToken,"ha") + "|";
		    	 
		     }
		     while(result.next())
		     { 
		    	 if(first)
		    	 {
		    		 first = false;
			    	 newToken = "u=" + result.getString("user_name") + "|";
			    	 newToken += "o=organization_1|";
			    	 newToken += "r=JRS_Employee|";
			    	 newToken += "pa1=" + n100M + "|";
			    	 newToken += "pa2=" + result.getString("user_name") + "|";
			    	 newToken += "pa3=" + FullName + "|";
			    	 newToken += "pa4='E'|";
			    	 newToken += "pa5=1|";
			    	 newToken += "pa6=1|";
			    	 newToken += "pa7=" + custId + "|";
			    	 newToken += "pa8=" + GetItemFromToken(oldToken,"aa") + "|";
			    	 newToken += "pa9=" + GetItemFromToken(oldToken,"ha") + "|";
			    	 
		    	 }
		    	// pa1+=result.getString("user_name") + ",";	 
		     }
		    }
		} catch (NamingException e) {
			// TODO Auto-generated catch block
	    	 if(shouldlog){log.info("Error when grabbing employee from db: " + e.getMessage());}
			e.printStackTrace();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
	    	 if(shouldlog){log.info("Error when grabbing employee from db: " + e.getMessage());}
	    	 e.printStackTrace();
		}
	        
		return newToken;
	}
	public String GetItemFromToken(String token, String item)
	{
		item = item + "=";
		if(token.contains(item))
		{
			int ending = token.length();
			if(token.indexOf("|", token.indexOf(item))>0)
			{
				ending = token.indexOf("|", token.indexOf(item));	
			}
			
			return token.substring(token.indexOf(item) + item.length(), ending);
		}
		else
		{
	    	 if(shouldlog){log.info("An item was requested from the token, but it was not found: " + item + " : " + token);}
			return "";
		}
	}

	public String getenablelogging() {
		return enablelogging;
	}
	
	public void setenablelogging(String enablelogging) {
		this.enablelogging = enablelogging;
	}

	public String getlogginglocation() {
		return logginglocation;
	}
	
	public void setlogginglocation(String logginglocation) {
		this.logginglocation = logginglocation;
	}

	public String getEBS() {
		return EBS;
	}
	
	public void setEBS(String EBS) {
		this.EBS = EBS;
	}

	public String getODS() {
		return ODS;
	}
	
	public void setODS(String ODS) {
		this.ODS = ODS;
	}
	public String getmonitorusername() {
		return monitorusername;
	}
	
	public void setmonitorusername(String monitorusername) {
		this.monitorusername = monitorusername;
	}
	public String getroleformonitoruser() {
		return roleformonitoruser;
	}
	
	public void setroleformonitoruser(String roleformonitoruser) {
		this.roleformonitoruser = roleformonitoruser;
	}

}
