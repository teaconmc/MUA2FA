package org.teacon.mua2fa.server;

import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.UnmodifiableCommentedConfig;
import com.google.common.base.Preconditions;
import com.google.common.net.HostAndPort;
import com.mojang.datafixers.util.Pair;
import it.unimi.dsi.fastutil.objects.Object2ObjectArrayMap;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.Util;
import net.neoforged.fml.config.IConfigSpec;
import net.neoforged.fml.config.ModConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringSubstitutor;
import org.apache.commons.text.lookup.StringLookup;
import org.apache.commons.text.lookup.StringLookupFactory;
import org.teacon.mua2fa.data.Ed25519;
import org.teacon.mua2fa.data.HashBase85;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.time.DateTimeException;
import java.time.Period;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.base.Preconditions.checkArgument;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class ConfigSpec implements IConfigSpec {
    private static final String TOKEN_SECRET_SIGN_KEY = "token.secretSignKey";
    private static final String TOKEN_VALIDITY_PERIOD = "token.validityPeriod";
    private static final String SERVER_EXTERNAL_URI = "server.externalUri";
    private static final String SERVER_INTERNAL_ADDRESS = "server.internalAddress";
    private static final String MUA_REQUIRE_UNION_AUTH = "mua.requireUnionAuth";
    private static final String MUA_UNION_AUTH_CLIENT_ID = "mua.unionAuthClientId";
    private static final String MUA_UNION_AUTH_CLIENT_SECRET = "mua.unionAuthClientSecret";

    private static final StringLookup LOOKUP = StringLookupFactory.INSTANCE.environmentVariableStringLookup();
    private static final StringSubstitutor SUB = new StringSubstitutor(LOOKUP);

    private final AtomicReference<Pair<EdECPublicKey, EdECPrivateKey>> tokenSecretSignKey = new AtomicReference<>();
    private final AtomicReference<Period> tokenValidityPeriod = new AtomicReference<>();

    private final AtomicReference<URI> serverExternalUri = new AtomicReference<>();
    private final AtomicReference<HostAndPort> serverInternalAddress = new AtomicReference<>();

    private final AtomicBoolean muaRequireUnionAuth = new AtomicBoolean(false);
    private final AtomicReference<String> muaUnionAuthClientId = new AtomicReference<>();
    private final AtomicReference<String> muaUnionAuthClientSecret = new AtomicReference<>();

    @Override
    public boolean isEmpty() {
        return false;
    }

    @Override
    public void validateSpec(ModConfig config) {
        Preconditions.checkArgument(config.getType() == ModConfig.Type.SERVER);
    }

    @Override
    public boolean isCorrect(UnmodifiableCommentedConfig config) {
        return collectCorrections(config).isEmpty();
    }

    @Override
    public void correct(CommentedConfig config) {
        collectCorrections(config).forEach(config::set);
    }

    @Override
    public void acceptConfig(@Nullable ILoadedConfig loadedConfig) {
        if (loadedConfig != null) {
            var config = loadedConfig.config();
            var corrections = collectCorrections(config);
            if (!corrections.isEmpty()) {
                corrections.forEach(config::set);
                loadedConfig.save();
            }
            this.tokenValidityPeriod.setOpaque(parsePositivePeriod(config.get(TOKEN_VALIDITY_PERIOD)).orElseThrow());
            this.tokenSecretSignKey.setOpaque(parseBase85KeyPair(config.get(TOKEN_SECRET_SIGN_KEY)).orElseThrow());
            this.serverExternalUri.setOpaque(parseUntrustedUri(config.get(SERVER_EXTERNAL_URI)).orElseThrow());
            this.serverInternalAddress.setOpaque(parseHostAndPort(config.get(SERVER_INTERNAL_ADDRESS)).orElseThrow());
            this.muaRequireUnionAuth.setOpaque(config.get(MUA_REQUIRE_UNION_AUTH));
            this.muaUnionAuthClientId.setOpaque(parseAscii(config.get(MUA_UNION_AUTH_CLIENT_ID)).orElseThrow());
            this.muaUnionAuthClientSecret.setOpaque(parseAscii(config.get(MUA_UNION_AUTH_CLIENT_SECRET)).orElseThrow());
        }
    }

    public Period getTokenValidityPeriod() {
        return this.tokenValidityPeriod.getOpaque();
    }

    public Pair<EdECPublicKey, EdECPrivateKey> getTokenSignKey() {
        return this.tokenSecretSignKey.getOpaque();
    }

    public URI getServerExternalUri() {
        return this.serverExternalUri.getOpaque();
    }

    public HostAndPort getServerInternalAddress() {
        return this.serverInternalAddress.getOpaque();
    }

    public boolean getMUARequireUnionAuth() {
        return this.muaRequireUnionAuth.getOpaque();
    }

    public String getMUAUnionAuthClientId() {
        return this.muaUnionAuthClientId.getOpaque();
    }

    public String getMUAUnionAuthClientSecret() {
        return this.muaUnionAuthClientSecret.getOpaque();
    }

    private static Map<String, ?> collectCorrections(UnmodifiableCommentedConfig config) {
        var result = new Object2ObjectArrayMap<String, Object>(7);
        if (!(config.get(TOKEN_VALIDITY_PERIOD) instanceof String s1) || parsePositivePeriod(s1).isEmpty()) {
            result.put(TOKEN_VALIDITY_PERIOD, "P1Y");
        }
        if (!(config.get(TOKEN_SECRET_SIGN_KEY) instanceof String s2) || parseBase85KeyPair(s2).isEmpty()) {
            result.put(TOKEN_SECRET_SIGN_KEY, HashBase85.encode(Ed25519.serialize(Ed25519.generate())));
        }
        if (!(config.get(SERVER_EXTERNAL_URI) instanceof String s3) || parseUntrustedUri(s3).isEmpty()) {
            result.put(SERVER_EXTERNAL_URI, "http://localhost:58888/");
        }
        if (!(config.get(SERVER_INTERNAL_ADDRESS) instanceof String s4) || parseHostAndPort(s4).isEmpty()) {
            result.put(SERVER_INTERNAL_ADDRESS, "0.0.0.0:58888");
        }
        if (!(config.get(MUA_REQUIRE_UNION_AUTH) instanceof Boolean)) {
            result.put(MUA_REQUIRE_UNION_AUTH, Boolean.FALSE);
        }
        if (!(config.get(MUA_UNION_AUTH_CLIENT_ID) instanceof String s6) || parseAscii(s6).isEmpty()) {
            result.put(MUA_UNION_AUTH_CLIENT_ID, "${MUA_UNION_AUTH_CLIENT_ID}");
        }
        if (!(config.get(MUA_UNION_AUTH_CLIENT_SECRET) instanceof String s7) || parseAscii(s7).isEmpty()) {
            result.put(MUA_UNION_AUTH_CLIENT_SECRET, "${MUA_UNION_AUTH_CLIENT_SECRET}");
        }
        return result;
    }

    private static Optional<Period> parsePositivePeriod(String input) {
        try {
            input = SUB.replace(input);
            var period = Period.parse(input);
            return period.isNegative() ? Optional.empty() : Optional.of(period);
        } catch (IllegalArgumentException | DateTimeException e) {
            return Optional.empty();
        }
    }

    private static Optional<Pair<EdECPublicKey, EdECPrivateKey>> parseBase85KeyPair(String input) {
        try {
            input = SUB.replace(input);
            checkArgument(input.length() == 40);
            return Optional.of(Ed25519.pair(HashBase85.decode(input)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static Optional<URI> parseUntrustedUri(String input) {
        try {
            return Optional.of(Util.parseAndValidateUntrustedUri(SUB.replace(input)));
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    private static Optional<HostAndPort> parseHostAndPort(String input) {
        try {
            return Optional.of(HostAndPort.fromString(SUB.replace(input)).withDefaultPort(58888));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static Optional<String> parseAscii(String input) {
        return Optional.of(SUB.replace(input)).map(StringUtils::strip).filter(StringUtils::isAsciiPrintable);
    }
}
