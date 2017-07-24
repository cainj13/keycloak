package org.keycloak.protocol.saml.mappers;

import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * User information mapper for when user property or attribute values should be combined or otherwise supplemented with constant text.
 *
 * Provides a way to match user properties via a template: {firstName}
 * And additionally, attributes can be accessed using the 'attribute' prefix: {attribute.preferredName}
 *
 * User properties and attributes can be combined with constant strings like so:
 * "Hello {attribute.preferredName}!  We won't call you {firstName} here."
 */
public class CombinedUserInformationStatementMapper extends AbstractSAMLProtocolMapper implements SAMLAttributeStatementMapper {
	public static final String PROVIDER_ID = "saml-combined-information-statement-mapper";

	/**
	 * When a piece of information is defined via the template {property} or {attribute.someattribute}, these choices define
	 * the behavior for when the specified variable is not found.
	 */
	public enum NullInformationBehavior {
		PRINT_NULL("Print 'null'", () -> "null"),
		EMPTY_STRING("Insert Empty String", () -> ""),
		THROW_EXCEPTION("Throw Exception", () -> {
			throw new MapperProcessingException("Required user attribute or property could not be mapped.");
		});

		private final String prettyString;
		private final Supplier<String> nullInformationString;
		private static final Map<String, NullInformationBehavior> reverseLookup = new HashMap<>();

		NullInformationBehavior(final String prettyString, final Supplier<String> nullInformationString) {
			this.prettyString = prettyString;
			this.nullInformationString = nullInformationString;
		}

		static {
			Arrays.stream(values()).forEach(nullInformationBehavior -> reverseLookup.put(nullInformationBehavior.prettyString, nullInformationBehavior));
		}

		/**
		 * @param prettyString Textual representation of the enum
		 * @return enumerated type mapped to the input text, EMPTY_STRING if text cannot be found.
		 */
		public static NullInformationBehavior fromPrettyString(final String prettyString) {
			return reverseLookup.getOrDefault(prettyString, EMPTY_STRING);
		}

		public String getPrettyString() {
			return prettyString;
		}

		public Supplier<String> getNullInformationString() {
			return nullInformationString;
		}
	}

	@Override
	public String getHelpText() {
		return "User information mapper for when user property or attribute values should be combined or otherwise supplemented with constant text.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return ProviderConfigurationBuilder.create()
				.property()
					.name("combined-user-information-string")
					.helpText("combined information and fields for a given user.  In the form '{attribute.firstInitial}.{lastName}@somewhere.com")
					.label("Combined User Information String")
					.type(ProviderConfigProperty.STRING_TYPE).add()
				.property()
					.name("null-information-behavior")
					.helpText("Defines what the mapper should do when null information is given for a filed")
					.label("Null Information Behavior")
					.type(ProviderConfigProperty.LIST_TYPE)
					.options(Arrays.stream(NullInformationBehavior.values()).map(NullInformationBehavior::getPrettyString).collect(Collectors.toList())).add()
				.build();
	}

	@Override
	public void transformAttributeStatement(final AttributeStatementType attributeStatement, final ProtocolMapperModel mappingModel, final KeycloakSession session, final UserSessionModel userSession, final AuthenticatedClientSessionModel clientSession) {

	}

	@Override
	public String getDisplayCategory() {
		return "saml";
	}

	@Override
	public String getDisplayType() {
		return "Combined User Information";
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	public static class CombinedUserInformationStringParser implements BiFunction<UserModel, String, String> {

		private final NullInformationBehavior nullInformationBehavior;

		public CombinedUserInformationStringParser(final NullInformationBehavior nullInformationBehavior) {
			this.nullInformationBehavior = nullInformationBehavior;
		}

		@Override
		public String apply(final UserModel userModel, final String s) {
			final StringTokenizer tokenizer = new StringTokenizer(s, "{}", true);
			final StringBuilder finalString = new StringBuilder();

			boolean inBrackets = false;
			while(tokenizer.hasMoreTokens()) {
				final String token = tokenizer.nextToken();

				if ("{".equals(token)) {
					inBrackets = true;
				} else if ("}".equals(token)) {
					inBrackets = false;
				} else if (inBrackets) {
					finalString.append(getTokenValue(userModel, token));
				} else {
					finalString.append(token);
				}
			}

			return finalString.toString();
		}

		private String getTokenValue(final UserModel user, final String token) {
			if (token == null) {
				return nullInformationBehavior.getNullInformationString().get();
			}

			final String userPropertyValue = ProtocolMapperUtils.getUserModelValue(user, token);
			return userPropertyValue;
		}
	}
}
