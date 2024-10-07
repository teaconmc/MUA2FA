package org.teacon.mua2fa.data;

import com.google.common.hash.HashCode;
import com.mojang.authlib.GameProfile;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;

import javax.annotation.ParametersAreNonnullByDefault;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.function.Predicate;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public record OAuthState(UUID id, String name, Instant expire,
                         HashCode signature, String cancelHint, String completeHint) {
    private static final Base64.Decoder DECODER;
    private static final Base64.Encoder ENCODER;

    public static final StreamCodec<ByteBuf, OAuthState> STREAM_CODEC;

    static {
        DECODER = Base64.getUrlDecoder();
        ENCODER = Base64.getUrlEncoder().withoutPadding();
        STREAM_CODEC = StreamCodec.composite(
                UUIDUtil.STREAM_CODEC, OAuthState::id,
                ByteBufCodecs.stringUtf8(16), OAuthState::name,
                ByteBufCodecs.VAR_LONG.map(Instant::ofEpochSecond, Instant::getEpochSecond), OAuthState::expire,
                HashBase85.ofStreamCodec(512), OAuthState::signature,
                ByteBufCodecs.stringUtf8(16383), OAuthState::cancelHint,
                ByteBufCodecs.stringUtf8(16383), OAuthState::completeHint, OAuthState::new);
    }

    public static OAuthState sign(UUID id, String name, Instant expire, EdECPrivateKey key) {
        var signature = Ed25519.sign(key, expire, new GameProfile(id, name), ByteBufCodecs.GAME_PROFILE);
        return new OAuthState(id, name, expire, signature, "", "");
    }

    public Predicate<Instant> verify(EdECPublicKey key) {
        var profile = new GameProfile(this.id, this.name);
        return Ed25519.verify(key, this.expire, this.signature, profile, ByteBufCodecs.GAME_PROFILE);
    }

    public OAuthState with(String cancelHint, String completeHint) {
        return new OAuthState(this.id, this.name, this.expire, this.signature, cancelHint, completeHint);
    }

    @Override
    public String toString() {
        // id: 16
        // name: 17
        // expire: 5
        // signature: 64
        // hints: 200 + 200
        var buf = Unpooled.buffer(504);
        STREAM_CODEC.encode(buf, this);
        return ENCODER.encodeToString(ByteBufUtil.getBytes(buf));
    }

    public static OAuthState fromString(String input) {
        var buf = Unpooled.wrappedBuffer(DECODER.decode(input));
        return STREAM_CODEC.decode(buf);
    }
}
