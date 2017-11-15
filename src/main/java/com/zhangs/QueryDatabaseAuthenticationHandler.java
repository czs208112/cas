package com.zhangs;

import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;
import java.security.GeneralSecurityException;


public class QueryDatabaseAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {
    @NotNull
    private String sql;

    public QueryDatabaseAuthenticationHandler() {
    }

    protected final HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential) throws GeneralSecurityException, PreventedException {
        String username = credential.getUsername();
        System.err.println("======= input username:(" + username + ")");
        String encryptedPassword = this.getPasswordEncoder().encode(credential.getPassword());
        System.err.println("======= input password:(" + encryptedPassword + ")");
        System.out.println("======= sql:(" + this.sql + ")");

        try {
            String dbPassword = (String) this.getJdbcTemplate().queryForObject(this.sql, String.class, new Object[]{username});
            System.err.println("++++++ dbPassword:(" + dbPassword.trim() + ")");
            if (!dbPassword.trim().equals(encryptedPassword)) {
                System.err.println("Password not match.");
                throw new FailedLoginException("Password does not match value on record.");
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
