package com.welldocs.j2ee8.security;

import static java.util.Arrays.asList;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

import java.util.HashSet;

import javax.enterprise.context.Dependent;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

@Dependent
public class TestIdentityStore implements IdentityStore {

    public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {

        if (usernamePasswordCredential.compareTo("user", "password")) {
            return new CredentialValidationResult("user", new HashSet<String>(asList("foo", "bar")));
        }
        if (usernamePasswordCredential.compareTo("user1", "password")) {
            return new CredentialValidationResult("user1", new HashSet<String>(asList("bar")));
        }
        return INVALID_RESULT;
    }
}
