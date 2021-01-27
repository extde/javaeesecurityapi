package com.welldocs.j2ee8.security;

import static org.glassfish.soteria.servlet.CookieHandler.removeCookie;

import static java.lang.Boolean.TRUE;
import static javax.security.enterprise.AuthenticationStatus.SUCCESS;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.interceptor.Interceptor;

import org.apache.commons.lang3.StringUtils;

@ApplicationScoped
@Alternative
@Priority(Interceptor.Priority.APPLICATION)
public class BspAuthenticationMechanism implements HttpAuthenticationMechanism {

    @Inject
    private IdentityStoreHandler identityStoreHandler;

    public AuthenticationStatus validateRequest(HttpServletRequest request,
                                                HttpServletResponse response,
                                                HttpMessageContext context)
            throws AuthenticationException {

        Credential credential = getCredentials(request);
        if (credential != null) {

            // logout
            cleanSubject(request, response, context);

            // initiate login even if principal is known
            CredentialValidationResult result = identityStoreHandler.validate(credential);

            if (result.getStatus() == VALID) {
                // enable session across multiple requests
                context.getMessageInfo().getMap().put("javax.servlet.http.registerSession", TRUE.toString());

                // Communicate the details of the authenticated user to the
                // container. In many cases the underlying handler will just store the details
                // and the container will actually handle the login after we return from
                // this method.
                return context.notifyContainerAboutLogin(
                        result.getCallerPrincipal(), result.getCallerGroups());
            } else {
                // unauthorized because of login failed
                return context.responseUnauthorized();
            }
        } else {
            if (request.getUserPrincipal() == null) {
                // unauthorized if principal is not known and no authentication performed
                return context.responseUnauthorized();
            }
        }

        // principal is known, no authentication done
        try {
            context.getHandler().handle(
                    new Callback[] {
                        new CallerPrincipalCallback(context.getClientSubject(), request.getUserPrincipal())
                    }
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return SUCCESS;
    }


    public void cleanSubject(HttpServletRequest request, HttpServletResponse response,
                             HttpMessageContext httpMessageContext) {
        httpMessageContext.cleanClientSubject();
        // remove JSESSIONID cookie
        removeCookie(request, response, request.getServletContext().getSessionCookieConfig().getName());
    }


    /**
     * Extract login credentials from request and returns specific credentials instance or <code>null</code>
     * if login credentials are missing in request.
     * @param request servlet request
     * @return specific credential instance or <code>null</code>
     */
    private Credential getCredentials(HttpServletRequest request) {
        Credential result = null;
        final String name = request.getParameter("name");
        final String pwd = request.getParameter("password");
        if (name != null && pwd != null) {
            Password password = new Password(pwd);
            result = new UsernamePasswordCredential(name, password);
        }
        return result;
    }



    /**
     * Check for logging in with as smart card. In that case you must not change the session id, as the client
     * and the server have to compare the same session id.
     *
     * @param req
     * @return
     */
    private boolean isSmartCardLoginActive(HttpServletRequest req) {
        boolean retVal = false;

        if (req != null) {
            retVal = !StringUtils.isEmpty(req.getParameter("smc_signature"));
        }

        return retVal;
    }


}
