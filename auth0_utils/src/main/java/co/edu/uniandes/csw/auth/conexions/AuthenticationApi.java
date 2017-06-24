/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package co.edu.uniandes.csw.auth.conexions;

import co.edu.uniandes.csw.auth.model.UserDTO;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author Asistente
 */
public class AuthenticationApi {

    private Properties prop = new Properties();
    private InputStream input = null;
    private static final String path = System.getenv("AUTH0_PROPERTIES");
   

    public AuthenticationApi() throws IOException, UnirestException, JSONException, InterruptedException, ExecutionException {
       
        
        try {
            input = new FileInputStream(path);
            try {
                prop.load(input);
            } catch (IOException ex) {
                Logger.getLogger(AuthenticationApi.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AuthenticationApi.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public HttpResponse<String> managementToken() throws UnirestException {
        Unirest.setTimeouts(1000, 10000);
        return Unirest.post(getProp().getProperty("accessToken").trim())
                .header("content-type", "application/json")
                .body("{\"grant_type\":\"client_credentials\","
                        + "\"client_id\": \"" + getProp().getProperty("managementClientId").trim() + "\","
                        + "\"client_secret\": \"" + getProp().getProperty("managementSecretKey").trim() + "\","
                        + "\"audience\":\"" + getProp().getProperty("managementAudience").trim() + "\"}").asString();

    }

    public HttpResponse<String> managementGetUser(String id) throws UnirestException, JSONException {

        Unirest.setTimeouts(1000, 10000);
        return Unirest.get(getProp().getProperty("users").trim() + "/" + id.replace("|", "%7C"))
                .header("content-type", "application/json")
                .header("Authorization", "Bearer " + getManagementAccessToken()).asString();
    }

    public HttpResponse<String> managementUpdateClientGrants() throws UnirestException, JSONException {
        Unirest.setTimeouts(1000, 10000);
        return Unirest.patch(getProp().getProperty("managementAudience").trim() + "clients/" + getProp().getProperty("authenticationClientId").trim())
                .header("content-type", "application/json")
                .header("Authorization", "Bearer " + getManagementAccessToken())
                .body("{\"grant_types\":[\"password\"]}")
                .asString();
    }
 
    public  HttpResponse<String> managementGetClientGrants(String clientId) throws UnirestException, JSONException{
    return Unirest.get(getProp().getProperty("managementAudience").trim() + "clients/" + getProp().getProperty(clientId).trim())
            .header("content-type", "application/json")
            .header("Authorization", "Bearer " + getManagementAccessToken()).asString();
  
    }
    
    public HttpResponse<String> authenticationToken(UserDTO dto) throws UnirestException {
        Unirest.setTimeouts(1000, 10000);
        return Unirest.post(getProp().getProperty("accessToken").trim())
                .header("content-type", "application/json")
                .body("{"
                        + "\"grant_type\":\"" + getProp().getProperty("grantType").trim() + "\","
                        + "\"username\":\"" + dto.getUserName() + "\","
                        + "\"password\":\"" + dto.getPassword() + "\","
                        + "\"client_id\":\"" + getProp().getProperty("authenticationClientId").trim() + "\","
                        + "\"client_secret\":\"" + getProp().getProperty("authenticationSecretKey").trim() + "\""
                        + "}").asString();
    }

    public HttpResponse<String> authenticationSignUP(UserDTO dto) throws UnirestException {
        Unirest.setTimeouts(1000, 10000);
        return Unirest.post(getProp().getProperty("signUp").trim())
                .header("content-type", "application/json")
                .body("{\"client_id\":\"" + getProp().getProperty("authenticationClientId").trim() + "\","
                        + "\"email\":\"" + dto.getEmail() + "\","
                        + "\"password\":\"" + dto.getPassword() + "\","
                        + "\"connection\":\"" + getProp().getProperty("connection").trim() + "\","
                        + "\"user_metadata\":{\"given_name\":\"" + dto.getGivenName() + "\","
                        + "\"email\":\"" + dto.getEmail() + "\","
                        + "\"username\":\"" + dto.getUserName() + "\","
                        + "\"middle_name\":\"" + dto.getMiddleName() + "\","
                        + "\"sur_name\":\"" + dto.getSurName() + "\"}}").asString();
    }

    public HttpResponse<String> authenticationUserInfo(UserDTO dto, HttpServletResponse rsp) throws UnirestException, JSONException {
        Unirest.setTimeouts(1000, 10000);
        return Unirest.get(getProp().getProperty("userInfo").trim())
                .header("Authorization", "Bearer " + getAuthenticationAccessToken(dto, rsp)).asString();
    }

    public void authenticationLogout() {
        Unirest.setTimeouts(1000, 10000);
        Unirest.get(getProp().getProperty("logout").trim());
    }

    public String getManagementAccessToken() throws UnirestException, JSONException {
        HttpResponse<String> res = managementToken();
        JSONObject json = new JSONObject(res.getBody());
        return (String) json.get("access_token");
    }

    public String getAuthenticationAccessToken(UserDTO dto, HttpServletResponse rsp) throws UnirestException, JSONException {
        HttpResponse<String> res = authenticationToken(dto);
        JSONObject json = new JSONObject(res.getBody());
        rsp.addHeader("id_token", json.get("id_token").toString());
        return (String) json.get("access_token");
    }
    //get user profile

    public String getSubject(UserDTO dto, HttpServletResponse rsp) throws UnirestException, JSONException {
        HttpResponse<String> res = authenticationUserInfo(dto, rsp);
        JSONObject json = new JSONObject(res.getBody());
        return json.get("sub").toString();
    }

    public void HttpServletResponseBinder(HttpResponse<String> rsp, HttpServletResponse res) throws IOException {
        res.setHeader("content-type", "application/json");
        res.setStatus(rsp.getCode());
        res.getWriter().print(rsp.getBody());
        res.flushBuffer();
    }

    public Jws<Claims> decryptToken(String token) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        String secret = getProp().getProperty("authenticationSecretKey").trim();
        Key signingKey = new SecretKeySpec(secret.getBytes(), signatureAlgorithm.getJcaName());
        Jws<Claims> j;
        
        try {
            if (token != null) {
                
                j = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
            } else {
                throw new SignatureException("no autenticado");
            }
        } catch (SignatureException se) {
            return null;
        }
        return j;
    }

    public Jws<Claims> decryptToken(HttpServletRequest req) {

        Cookie[] cookie = req.getCookies();
        String jwt = null;

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        String secret = getProp().getProperty("authenticationSecretKey").trim();
        Key signingKey = new SecretKeySpec(secret.getBytes(), signatureAlgorithm.getJcaName());
        Jws<Claims> j;
        for (Cookie c : cookie) {
            if ("id_token".equals(c.getName())) {
                jwt = c.getValue();
            }
        }
        try {
            if (jwt != null) {
                j = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(jwt);
            } else {
                throw new SignatureException("no autenticado");
            }
        } catch (SignatureException se) {
            return null;
        }
        return j;
    }

    /**
     * @return the prop
     */
    public Properties getProp() {
        return prop;
    }

    /**
     * @param prop the prop to set
     */
    public void setProp(Properties prop) {
        this.prop = prop;
    }
}
