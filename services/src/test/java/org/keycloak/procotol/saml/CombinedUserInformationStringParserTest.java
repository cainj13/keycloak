package org.keycloak.procotol.saml;

import org.junit.Test;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.saml.mappers.CombinedUserInformationStatementMapper;

import java.util.function.BiFunction;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CombinedUserInformationStringParserTest {

	@Test
	public void shouldParseWhenNullUserStaticString() {
		final BiFunction<UserModel, String, String> parser = new CombinedUserInformationStatementMapper.CombinedUserInformationStringParser(CombinedUserInformationStatementMapper.NullInformationBehavior.EMPTY_STRING);
		assertThat(parser.apply(null, "foo"), equalTo("foo"));
	}

	@Test
	public void shouldUseNullActionWhenNullUser() {
		final BiFunction<UserModel, String, String> parser = new CombinedUserInformationStatementMapper.CombinedUserInformationStringParser(CombinedUserInformationStatementMapper.NullInformationBehavior.EMPTY_STRING);
		assertThat(parser.apply(null, "foo {firstName}"), equalTo("foo "));
	}

	@Test
	public void shouldUseUserPropertyWhenGiven() {
		UserModel userModel = mock(UserModel.class);
		when(userModel.getUsername()).thenReturn("bar");

		final BiFunction<UserModel, String, String> parser = new CombinedUserInformationStatementMapper.CombinedUserInformationStringParser(CombinedUserInformationStatementMapper.NullInformationBehavior.EMPTY_STRING);
		assertThat(parser.apply(userModel, "foo {firstName}"), equalTo("foo bar"));
	}
}
