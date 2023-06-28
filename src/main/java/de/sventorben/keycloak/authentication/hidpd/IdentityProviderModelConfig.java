package de.sventorben.keycloak.authentication.hidpd;

import java.util.Arrays;
import java.util.stream.Stream;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.HardcodedAttributeMapper;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.jboss.logging.Logger;

final class IdentityProviderModelConfig {

    private static final String DOMAINS_ATTRIBUTE_KEY = "home.idp.discovery.domains";
    private static final Logger LOG = Logger.getLogger(IdentityProviderModelConfig.class);

    private final IdentityProviderModel identityProviderModel;
    private final AuthenticationFlowContext context;

    IdentityProviderModelConfig(AuthenticationFlowContext context, IdentityProviderModel identityProviderModel) {
        this.identityProviderModel = identityProviderModel;
        this.context = context;
    }

    boolean hasDomain(String userAttributeName, String domain) {
        return getDomains(userAttributeName).anyMatch(domain::equalsIgnoreCase);
    }

    private Stream<String> getDomains(String userAttributeName) {
        String key = getDomainConfigKey(userAttributeName);
        String domainsAttribute = identityProviderModel.getConfig().getOrDefault(key, "");
        if (domainsAttribute.length() == 0) {
        	 Stream<IdentityProviderMapperModel> mappers = context.getRealm().getIdentityProviderMappersByAliasStream(identityProviderModel.getAlias());
        	 IdentityProviderMapperModel mapper = mappers.filter(p -> DOMAINS_ATTRIBUTE_KEY.equals(p.getConfig().get(HardcodedAttributeMapper.ATTRIBUTE)))
        	 		.findFirst()
        	 		.orElse(null);
        	 if (mapper != null) {
        		 domainsAttribute = mapper.getConfig().getOrDefault(HardcodedAttributeMapper.ATTRIBUTE_VALUE, "");
                 LOG.tracef("Found attribute mapper for '%s' with domain '%s'", DOMAINS_ATTRIBUTE_KEY, domainsAttribute);
        	 } else {
                 LOG.tracef("No attribute mapper found for '%s'", DOMAINS_ATTRIBUTE_KEY);
             }
        }
        return Arrays.stream(Constants.CFG_DELIMITER_PATTERN.split(domainsAttribute));
    }

    private String getDomainConfigKey(String userAttributeName) {
        String key = DOMAINS_ATTRIBUTE_KEY;
        if (userAttributeName != null) {
            final String candidateKey = DOMAINS_ATTRIBUTE_KEY + "." + userAttributeName;
            if (identityProviderModel.getConfig().containsKey(candidateKey)) {
                key = candidateKey;
            }
        }
        return key;
    }

}
