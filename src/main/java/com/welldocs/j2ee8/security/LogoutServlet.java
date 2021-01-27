package com.welldocs.j2ee8.security;

import java.io.IOException;

import javax.annotation.security.DeclareRoles;
import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*
@BasicAuthenticationMechanismDefinition(
        realmName="${'jaspitest'}"
)
 */

@WebServlet("/logout")
//@DeclareRoles({ "foo", "bar", "kaz"})
//@ServletSecurity(@HttpConstraint(rolesAllowed = "foo"))
public class LogoutServlet extends HttpServlet {

    private static final Log LOG = LogFactory.getLog(LogoutServlet.class);


    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {


        String webName = null;
        if (request.getUserPrincipal() != null) {
            webName = request.getUserPrincipal().getName();
        }

        LOG.info("logout for web username: " + webName);
        request.logout();
    }
}
