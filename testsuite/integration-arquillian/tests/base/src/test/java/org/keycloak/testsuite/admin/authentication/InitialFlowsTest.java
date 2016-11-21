/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.admin.authentication;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class InitialFlowsTest extends AbstractAuthenticationTest {

    private final HashMap<String, AuthenticatorConfigRepresentation> configs = new HashMap<>();
    private final HashMap<String, AuthenticatorConfigRepresentation> expectedConfigs = new HashMap<>();

    {
        expectedConfigs.put("idp-review-profile", newConfig("review profile config", new String[]{"update.profile.on.first.login", "missing"}));
        expectedConfigs.put("idp-create-user-if-unique", newConfig("create unique user config", new String[]{"require.password.update.after.registration", "false"}));
    }

    @Test
    public void testInitialFlows() {

        final List<FlowExecutions> result = new LinkedList<>();

        // get all flows
        final List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        for (final AuthenticationFlowRepresentation flow : flows) {
            // get all executions for flow
            final List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions(flow.getAlias());

            for (final AuthenticationExecutionInfoRepresentation exec : executionReps) {
                // separately load referenced configurations
                final String configId = exec.getAuthenticationConfig();
                if (configId != null && !configs.containsKey(configId)) {
                    configs.put(configId, authMgmtResource.getAuthenticatorConfig(configId));
                }
            }
            result.add(new FlowExecutions(flow, executionReps));
        }

        // make sure received flows and their details are as expected
        compare(expectedFlows(), orderAlphabetically(result));
    }

    private void compare(final List<FlowExecutions> expected, final List<FlowExecutions> actual) {
        Assert.assertEquals("Flow count", expected.size(), actual.size());
        final Iterator<FlowExecutions> it1 = expected.iterator();
        final Iterator<FlowExecutions> it2 = actual.iterator();
        while (it1.hasNext()) {
            final FlowExecutions fe1 = it1.next();
            final FlowExecutions fe2 = it2.next();

            compareFlows(fe1.flow, fe2.flow);
            compareExecutionsInfo(fe1.executions, fe2.executions);
        }
    }


    private void compareExecutionsInfo(final List<AuthenticationExecutionInfoRepresentation> expected, final List<AuthenticationExecutionInfoRepresentation> actual) {
        Assert.assertEquals("Executions count", expected.size(), actual.size());
        final Iterator<AuthenticationExecutionInfoRepresentation> it1 = expected.iterator();
        final Iterator<AuthenticationExecutionInfoRepresentation> it2 = actual.iterator();
        while (it1.hasNext()) {
            final AuthenticationExecutionInfoRepresentation exe1 = it1.next();
            final AuthenticationExecutionInfoRepresentation exe2 = it2.next();

            compareExecutionWithConfig(exe1, exe2);
        }
    }

    private void compareExecutionWithConfig(final AuthenticationExecutionInfoRepresentation expected, final AuthenticationExecutionInfoRepresentation actual) {
        super.compareExecution(expected, actual);
        compareAuthConfig(expected, actual);
    }

    private void compareAuthConfig(final AuthenticationExecutionInfoRepresentation expected, final AuthenticationExecutionInfoRepresentation actual) {
        final AuthenticatorConfigRepresentation cfg1 = expectedConfigs.get(expected.getProviderId());
        final AuthenticatorConfigRepresentation cfg2 = configs.get(actual.getAuthenticationConfig());

        if (cfg1 == null && cfg2 == null) {
            return;
        }
        Assert.assertEquals("Execution configuration alias", cfg1.getAlias(), cfg2.getAlias());
        Assert.assertEquals("Execution configuration params", cfg1.getConfig(), cfg2.getConfig());
    }

    private List<FlowExecutions> orderAlphabetically(final List<FlowExecutions> result) {
        final List<FlowExecutions> sorted = new ArrayList<>(result);
        Collections.sort(sorted);
        return sorted;
    }

    private LinkedList<FlowExecutions> expectedFlows() {
        final LinkedList<FlowExecutions> expected = new LinkedList<>();

        AuthenticationFlowRepresentation flow = newFlow("browser", "browser based authentication", "basic-flow", true, true);
        addExecExport(flow, null, false, "auth-cookie", false, null, ALTERNATIVE, 10);
        addExecExport(flow, null, false, "auth-spnego", false, null, DISABLED, 20);
        addExecExport(flow, null, false, "identity-provider-redirector", false, null, ALTERNATIVE, 25);
        addExecExport(flow, "forms", false, null, true, null, ALTERNATIVE, 30);

        List<AuthenticationExecutionInfoRepresentation> execs = new LinkedList<>();
        addExecInfo(execs, "Cookie", "auth-cookie", false, 0, 0, ALTERNATIVE, null, new String[]{ALTERNATIVE, DISABLED});
        addExecInfo(execs, "Kerberos", "auth-spnego", false, 0, 1, DISABLED, null, new String[]{ALTERNATIVE, REQUIRED, DISABLED});
        addExecInfo(execs, "Identity Provider Redirector", "identity-provider-redirector", true, 0, 2, ALTERNATIVE, null, new String[]{ALTERNATIVE, DISABLED});
        addExecInfo(execs, "forms", null, false, 0, 3, ALTERNATIVE, true, new String[]{ALTERNATIVE, REQUIRED, DISABLED});
        addExecInfo(execs, "Username Password Form", "auth-username-password-form", false, 1, 0, REQUIRED, null, new String[]{REQUIRED});
        addExecInfo(execs, "OTP Form", "auth-otp-form", false, 1, 1, OPTIONAL, null, new String[]{REQUIRED, OPTIONAL, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        flow = newFlow("clients", "Base authentication for clients", "client-flow", true, true);
        addExecExport(flow, null, false, "client-secret", false, null, ALTERNATIVE, 10);
        addExecExport(flow, null, false, "client-jwt", false, null, ALTERNATIVE, 20);

        execs = new LinkedList<>();
        addExecInfo(execs, "Client Id and Secret", "client-secret", false, 0, 0, ALTERNATIVE, null, new String[]{ALTERNATIVE, DISABLED});
        addExecInfo(execs, "Signed Jwt", "client-jwt", false, 0, 1, ALTERNATIVE, null, new String[]{ALTERNATIVE, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        flow = newFlow("direct grant", "OpenID Connect Resource Owner Grant", "basic-flow", true, true);
        addExecExport(flow, null, false, "direct-grant-validate-username", false, null, REQUIRED, 10);
        addExecExport(flow, null, false, "direct-grant-validate-password", false, null, REQUIRED, 20);
        addExecExport(flow, null, false, "direct-grant-validate-otp", false, null, OPTIONAL, 30);

        execs = new LinkedList<>();
        addExecInfo(execs, "Username Validation", "direct-grant-validate-username", false, 0, 0, REQUIRED, null, new String[]{REQUIRED});
        addExecInfo(execs, "Password", "direct-grant-validate-password", false, 0, 1, REQUIRED, null, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "OTP", "direct-grant-validate-otp", false, 0, 2, OPTIONAL, null, new String[]{REQUIRED, OPTIONAL, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        flow = newFlow("first broker login", "Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account",
                "basic-flow", true, true);
        addExecExport(flow, null, false, "idp-review-profile", false, "review profile config", REQUIRED, 10);
        addExecExport(flow, null, false, "idp-create-user-if-unique", false, "create unique user config", ALTERNATIVE, 20);
        addExecExport(flow, "Handle Existing Account", false, null, true, null, ALTERNATIVE, 30);

        execs = new LinkedList<>();
        addExecInfo(execs, "Review Profile", "idp-review-profile", true, 0, 0, REQUIRED, null, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "Create User If Unique", "idp-create-user-if-unique", true, 0, 1, ALTERNATIVE, null, new String[]{ALTERNATIVE, REQUIRED, DISABLED});
        addExecInfo(execs, "Handle Existing Account", null, false, 0, 2, ALTERNATIVE, true, new String[]{ALTERNATIVE, REQUIRED, DISABLED});
        addExecInfo(execs, "Confirm link existing account", "idp-confirm-link", false, 1, 0, REQUIRED, null, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "Verify existing account by Email", "idp-email-verification", false, 1, 1, ALTERNATIVE, null, new String[]{ALTERNATIVE, REQUIRED, DISABLED});
        addExecInfo(execs, "Verify Existing Account by Re-authentication", null, false, 1, 2, ALTERNATIVE, true, new String[]{ALTERNATIVE, REQUIRED, DISABLED});
        addExecInfo(execs, "Username Password Form for identity provider reauthentication", "idp-username-password-form", false, 2, 0, REQUIRED, null, new String[]{REQUIRED});
        addExecInfo(execs, "OTP Form", "auth-otp-form", false, 2, 1, OPTIONAL, null, new String[]{REQUIRED, OPTIONAL, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        flow = newFlow("registration", "registration flow", "basic-flow", true, true);
        addExecExport(flow, "registration form", false, "registration-page-form", true, null, REQUIRED, 10);

        execs = new LinkedList<>();
        addExecInfo(execs, "registration form", "registration-page-form", false, 0, 0, REQUIRED, true, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "Registration User Creation", "registration-user-creation", false, 1, 0, REQUIRED, null, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "Profile Validation", "registration-profile-action", false, 1, 1, REQUIRED, null, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "Password Validation", "registration-password-action", false, 1, 2, REQUIRED, null, new String[]{REQUIRED, DISABLED});
        addExecInfo(execs, "Recaptcha", "registration-recaptcha-action", true, 1, 3, DISABLED, null, new String[]{REQUIRED, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        flow = newFlow("reset credentials", "Reset credentials for a user if they forgot their password or something", "basic-flow", true, true);
        addExecExport(flow, null, false, "reset-credentials-choose-user", false, null, REQUIRED, 10);
        addExecExport(flow, null, false, "reset-credential-email", false, null, REQUIRED, 20);
        addExecExport(flow, null, false, "reset-password", false, null, REQUIRED, 30);
        addExecExport(flow, null, false, "reset-otp", false, null, OPTIONAL, 40);

        execs = new LinkedList<>();
        addExecInfo(execs, "Choose User", "reset-credentials-choose-user", false, 0, 0, REQUIRED, null, new String[]{REQUIRED});
        addExecInfo(execs, "Send Reset Email", "reset-credential-email", false, 0, 1, REQUIRED, null, new String[]{REQUIRED});
        addExecInfo(execs, "Reset Password", "reset-password", false, 0, 2, REQUIRED, null, new String[]{REQUIRED, OPTIONAL, DISABLED});
        addExecInfo(execs, "Reset OTP", "reset-otp", false, 0, 3, OPTIONAL, null, new String[]{REQUIRED, OPTIONAL, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        flow = newFlow("saml ecp", "SAML ECP Profile Authentication Flow", "basic-flow", true, true);
        addExecExport(flow, null, false, "http-basic-authenticator", false, null, REQUIRED, 10);

        execs = new LinkedList<>();
        addExecInfo(execs, "HTTP Basic Authentication", "http-basic-authenticator", false, 0, 0, REQUIRED, null, new String[]{REQUIRED, ALTERNATIVE, OPTIONAL, DISABLED});
        expected.add(new FlowExecutions(flow, execs));

        return expected;
    }

    private void addExecExport(final AuthenticationFlowRepresentation flow, final String flowAlias, final boolean userSetupAllowed,
                               final String authenticator, final boolean authenticatorFlow, final String authenticatorConfig,
                               final String requirement, final int priority) {

        final AuthenticationExecutionExportRepresentation rep = newExecutionExportRepresentation(flowAlias, userSetupAllowed,
                authenticator, authenticatorFlow, authenticatorConfig, requirement, priority);

        List<AuthenticationExecutionExportRepresentation> execs = flow.getAuthenticationExecutions();
        if (execs == null) {
            execs = new ArrayList<>();
            flow.setAuthenticationExecutions(execs);
        }
        execs.add(rep);
    }

    private AuthenticationExecutionExportRepresentation newExecutionExportRepresentation(final String flowAlias, final boolean userSetupAllowed, final String authenticator, final boolean authenticatorFlow, final String authenticatorConfig, final String requirement, final int priority) {
        final AuthenticationExecutionExportRepresentation rep = new AuthenticationExecutionExportRepresentation();
        rep.setFlowAlias(flowAlias);
        rep.setUserSetupAllowed(userSetupAllowed);
        rep.setAuthenticator(authenticator);
        rep.setAutheticatorFlow(authenticatorFlow);
        rep.setAuthenticatorConfig(authenticatorConfig);
        rep.setRequirement(requirement);
        rep.setPriority(priority);
        return rep;
    }

    private static class FlowExecutions implements Comparable<FlowExecutions> {
        AuthenticationFlowRepresentation flow;
        List<AuthenticationExecutionInfoRepresentation> executions;

        FlowExecutions(final AuthenticationFlowRepresentation flow, final List<AuthenticationExecutionInfoRepresentation> executions) {
            this.flow = flow;
            this.executions = executions;
        }

        @Override
        public int compareTo(final FlowExecutions o) {
            return flow.getAlias().compareTo(o.flow.getAlias());
        }
    }
}
