package org.teacon.mua2fa.data;

import com.google.common.base.Predicates;
import com.google.common.hash.HashCode;
import com.google.common.primitives.Longs;
import com.mojang.datafixers.util.Pair;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.VarLong;
import net.minecraft.network.codec.StreamCodec;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.teacon.mua2fa.MUA2FA;

import javax.annotation.ParametersAreNonnullByDefault;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.function.Predicate;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class Ed25519 {
    private static final KeyFactory FACTORY;
    private static final KeyPairGenerator GENERATOR;
    private static final EdDSANamedCurveSpec CURVE_SPEC;
    private static final Marker MARKER = MarkerManager.getMarker("Ed25519");

    static {
        try {
            FACTORY = KeyFactory.getInstance("Ed25519");
            GENERATOR = KeyPairGenerator.getInstance("Ed25519");
            CURVE_SPEC = EdDSANamedCurveTable.ED_25519_CURVE_SPEC;
        } catch (GeneralSecurityException e) {
            MUA2FA.LOGGER.error(MARKER, "Failed to initialize ED25519 factories", e);
            throw new RuntimeException(e);
        }
    }

    private Ed25519() {
        throw new UnsupportedOperationException();
    }

    public static Pair<EdECPublicKey, EdECPrivateKey> generate() {
        var keyPair = GENERATOR.generateKeyPair();
        return Pair.of((EdECPublicKey) keyPair.getPublic(), (EdECPrivateKey) keyPair.getPrivate());
    }

    public static Pair<EdECPublicKey, EdECPrivateKey> pair(HashCode bytes) {
        try {
            var specPrivateWrapped = new EdDSAPrivateKeySpec(bytes.asBytes(), CURVE_SPEC);
            var specPublicWrapped = new EdDSAPublicKeySpec(specPrivateWrapped.getA(), CURVE_SPEC);
            var specPrivate = new PKCS8EncodedKeySpec(new EdDSAPrivateKey(specPrivateWrapped).getEncoded());
            var specPublic = new X509EncodedKeySpec(new EdDSAPublicKey(specPublicWrapped).getEncoded());
            var keyPrivate = (EdECPrivateKey) FACTORY.generatePrivate(specPrivate);
            var keyPublic = (EdECPublicKey) FACTORY.generatePublic(specPublic);
            return Pair.of(keyPublic, keyPrivate);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static EdECPublicKey single(HashCode bytes) {
        try {
            var specPublicWrapped = new EdDSAPublicKeySpec(bytes.asBytes(), CURVE_SPEC);
            var specPublic = new X509EncodedKeySpec(new EdDSAPublicKey(specPublicWrapped).getEncoded());
            return (EdECPublicKey) FACTORY.generatePublic(specPublic);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static HashCode serialize(EdECPublicKey key) {
        try {
            var specPublic = FACTORY.getKeySpec(key, X509EncodedKeySpec.class);
            return HashCode.fromBytes(new EdDSAPublicKey(specPublic).getAbyte());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static HashCode serialize(Pair<EdECPublicKey, EdECPrivateKey> pair) {
        try {
            var specPrivate = FACTORY.getKeySpec(pair.getSecond(), PKCS8EncodedKeySpec.class);
            return HashCode.fromBytes(new EdDSAPrivateKey(specPrivate).getAbyte());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static <T> HashCode sign(EdECPrivateKey key, Instant expire,
                                    T input, StreamCodec<? super FriendlyByteBuf, T> codec) {
        try {
            var buffer = new FriendlyByteBuf(Unpooled.buffer());
            codec.encode(buffer, input);
            var sign = Signature.getInstance("Ed25519");
            sign.initSign(key);
            sign.update(buffer.array(), 0, buffer.writerIndex());
            sign.update(ByteBufUtil.getBytes(VarLong.write(Unpooled.buffer(5), expire.getEpochSecond())));
            return HashCode.fromBytes(sign.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static <T> Predicate<Instant> verify(EdECPublicKey key, Instant expire, HashCode digest,
                                                T input, StreamCodec<? super FriendlyByteBuf, T> codec) {
        try {
            var buffer = new FriendlyByteBuf(Unpooled.buffer());
            codec.encode(buffer, input);
            var sign = Signature.getInstance("Ed25519");
            sign.initVerify(key);
            sign.update(buffer.array(), 0, buffer.writerIndex());
            sign.update(ByteBufUtil.getBytes(VarLong.write(Unpooled.buffer(5), expire.getEpochSecond())));
            return sign.verify(digest.asBytes()) ? Predicate.not(expire::isBefore) : Predicates.alwaysFalse();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
