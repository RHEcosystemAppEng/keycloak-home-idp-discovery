package de.sventorben.keycloak.authentication.hidpd;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.HardcodedAttributeMapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdentityProviderModelConfigTest {
	
	@Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthenticationFlowContext context;

    private static final String DOMAINS_ATTRIBUTE_KEY = "home.idp.discovery.domains";

    @BeforeEach
    void setUp() {
        when(context.getRealm()).thenReturn(mock(RealmModel.class));
        when(context.getUser()).thenReturn(mock(UserModel.class));
    }

    @ParameterizedTest
    @CsvSource(value = {
        "null, null, null, null, false",
        "null, email, null, null, false",
        "null, null, null, '', false",
        "null, email, null, '', false",
        "null, null, null, example.net##example.org, false",
        "null, null, null, example.com##example.org, true",
        "null, email, null, example.net##example.org, false",
        "null, email, null, example.com##example.org, true",
        "email, email, null, example.net##example.org, false",
        "email, email, null, example.com##example.org, true",
        "email, email, example.net##example.org, example.com##example.org, false",
        "email, email, example.com##example.org, example.net##example.org, true",
        "email, email, example.net##example.org, null, false",
        "email, email, example.com##example.org, null, true",
        "email, email, example.com##example.org, , true",
        "email, email, '', example.com##example.org, false",
    }, nullValues = { "null" })
    void testHasDomain(String userAttributeName, String userAttributeNameQuery, String userAttributeDomains, String defaultDomains, boolean expected) {
        Map<String, String> config = new HashMap<>();
        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setConfig(config);
        IdentityProviderModelConfig cut = new IdentityProviderModelConfig(context, idp);
        if (userAttributeName != null && userAttributeDomains != null) {
            config.put(DOMAINS_ATTRIBUTE_KEY + "." + userAttributeName, userAttributeDomains);
        }
        if (defaultDomains != null) {
            config.put(DOMAINS_ATTRIBUTE_KEY, defaultDomains);
        }

        boolean result = cut.hasDomain(userAttributeNameQuery, "example.com");

        assertThat(result).isEqualTo(expected);
    }
    
    @ParameterizedTest
    @CsvSource(value = {
    	"null, null, false",
        "email, example.com##example.org, true",
        "email, example.net##example.org, false",
    }, nullValues = { "null" })
    void testMapperHasDomain(String userAttributeNameQuery, String defaultDomains, boolean expected) {
        
    	Map<String, String> config = new HashMap<>();
        IdentityProviderModel identityProviderModel = new IdentityProviderModel();
        identityProviderModel.setAlias("keycloak-oidc");
        identityProviderModel.setConfig(config);
        
        IdentityProviderMapperRepresentation rep = new IdentityProviderMapperRepresentation();
        rep.setName("domain-mapper");
        rep.setIdentityProviderAlias(identityProviderModel.getAlias());
        rep.setIdentityProviderMapper("hardcoded-attribute-idp-mapper");
        rep.getConfig().put(HardcodedAttributeMapper.ATTRIBUTE, DOMAINS_ATTRIBUTE_KEY);
        rep.getConfig().put(HardcodedAttributeMapper.ATTRIBUTE_VALUE, defaultDomains);
        
        IdentityProviderMapperModel mapperModel = RepresentationToModel.toModel(rep);
        IdentityProviderMapperModel[] mappers = {mapperModel} ;
        
        given(context.getRealm().getIdentityProviderMappersByAliasStream(mapperModel.getIdentityProviderAlias()))
        .willReturn(Arrays.stream(mappers));
        
        IdentityProviderModelConfig cut = new IdentityProviderModelConfig(context, identityProviderModel);
        boolean result = cut.hasDomain(userAttributeNameQuery, "example.com");

        assertThat(result).isEqualTo(expected);
    }
}
