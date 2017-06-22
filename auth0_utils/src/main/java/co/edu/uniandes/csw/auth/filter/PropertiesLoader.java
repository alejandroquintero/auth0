/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package co.edu.uniandes.csw.auth.filter;

import io.jsonwebtoken.lang.Collections;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Properties;

import java.lang.Class;
import java.lang.Object;
import java.util.concurrent.TimeUnit;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;


/**
 *
 * @author Asistente
 */
public class PropertiesLoader {
    
  private Properties prop;
  private InputStream input;
  private  String file;
  
  public PropertiesLoader() throws FileNotFoundException, IOException{
  //resolve a cache manager
 
  prop=new Properties();
  file=this.getClass().getProtectionDomain()
             .getCodeSource().getLocation().toString()
             .split("target")[0].substring(6)
             .concat("src/main/java/co/edu/uniandes/csw"
                     + "/auth/properties/auth0.properties");
  input = new FileInputStream(file);
  prop.load(input);
  }
  
  public List<String> getPropertyAsList(String property){
  return  Collections.arrayToList(prop.getProperty(property).trim().split(","));   
  }
   
  public  String getPropertyAsString(String property){
  return   prop.getProperty(property).trim();
  }
  
  public Boolean containsKey(String s){
  return prop.containsKey(s);
  }
  public String getRole(String s){
      return prop.getProperty(s).trim().split(" ")[0];
  }
   
  public Boolean containsRole(String s){
  if(containsKey(s))
      if(prop.getProperty(s).matches("[A-Za-z ,]+"))
        return true;
   return false;  
  }
  
  public String getMethodsAsString(String s){
  return prop.getProperty(s).trim().split(" ")[1];
  }
  
  public List<String> getMethodsAsList(String s){
  return Collections.arrayToList(prop.getProperty(s).trim().split(" ")[1].split(","));
  }
  
  public Boolean isMethodList(String s){
      return prop.getProperty(s).trim().split(" ")[1].contains(",");
  }
  
  public String methodMapper(String s){
      String str;
   switch(s){
       case "POST": 
       str="create";
       break;
       case "GET": 
       str="read";
       break;
       case "PUT": 
       str="edit";
       break;
       case "DELETE": 
       str="delete";
       break;
       default:
           str="";
   }
   return str;
  }
  
}
