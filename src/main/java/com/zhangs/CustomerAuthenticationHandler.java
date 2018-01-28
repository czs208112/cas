package com.zhangs;

import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.AccountDisabledException;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.util.Map;


public class CustomerAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {
    @NotNull
    private String sql;

    public CustomerAuthenticationHandler() {
    }

    protected final HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential) throws GeneralSecurityException, PreventedException {
        String username = credential.getUsername();
        System.err.println("======= input username:(" + username + ")");
        String encryptedPassword = this.getPasswordEncoder().encode(credential.getPassword());
        System.err.println("======= input password:(" + encryptedPassword + ")");
        System.out.println("======= sql:(" + this.sql + ")");

        try {
            Map<String, Object> userMap = this.getJdbcTemplate().queryForMap(this.sql, username);

            System.err.println("++++++ dbPassword:(" + userMap.get("password") + ")");
            if (null == userMap || !userMap.get("password").equals(encryptedPassword)) {
                System.err.println("Password not match.");
                throw new FailedLoginException("Password does not match value on record.");
            }
            if (userMap.get("isenabled").toString().trim().equals("0")) {
                throw new AccountDisabledException("Account does locked.");
            }
        } catch (IncorrectResultSizeDataAccessException var5) {
            if (var5.getActualSize() == 0) {
                throw new AccountNotFoundException(username + " not found with SQL query");
            }

            var5.printStackTrace();
            throw new FailedLoginException("Multiple records found for " + username);
        } catch (DataAccessException var6) {
            var6.printStackTrace();
            throw new PreventedException("SQL exception while executing query for " + username, var6);
        }
        return createHandlerResult(credential, this.principalFactory.createPrincipal(username), null);
//        return this.createHandlerResult(credential, new SimplePrincipal(username), (List)null);
    }

    public void setSql(String sql) {
        this.sql = sql;
    }
}
