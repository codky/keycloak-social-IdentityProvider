package com.nexgrid.keycloaksocialnaver;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KakaoIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    private final static Logger log = LoggerFactory.getLogger(KakaoIdentityProvider.class);

    public static final String AUTH_URL = "https://kauth.kakao.com/oauth/authorize";
    public static final String TOKEN_URL = "https://kauth.kakao.com/oauth/token";
    public static final String PROFILE_URL = "https://kapi.kakao.com/v2/user/me";
    public static final String DEFAULT_SCOPE = "account_email,openid,profile_nickname";

    public KakaoIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) { // 네이버 profile Endopoint 주소 반환
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {

        log.info("extractIdentityFromProfile.profile = " + profile);
        long longtypevalue = profile.get("id").asLong();
        String id = String.valueOf(longtypevalue);
        BrokeredIdentityContext user = new BrokeredIdentityContext(id);
        log.info("extractIdentityFromProfile.user = " + user);

        String nickname = profile.get("properties").get("nickname").asText();

        user.setIdpConfig(getConfig());
        user.setUsername(nickname);
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).param("access_token", accessToken).asJson();
            log.info("doGetFederatedIdentity.profile = " + profile);

            BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);
            log.info("doGetFederatedIdentity.user = " + user);

            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from kakao.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
}
