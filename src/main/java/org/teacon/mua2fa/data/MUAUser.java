package org.teacon.mua2fa.data;

import com.mojang.authlib.GameProfile;
import com.mojang.datafixers.util.Pair;
import com.mojang.serialization.Codec;
import com.mojang.serialization.codecs.RecordCodecBuilder;
import io.netty.buffer.ByteBuf;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;

import javax.annotation.ParametersAreNonnullByDefault;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.util.List;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public record MUAUser(String sub, String nickname, String email) {
    public static final Codec<MUAUser> CODEC;
    public static final StreamCodec<ByteBuf, MUAUser> STREAM_CODEC;

    static {
        CODEC = RecordCodecBuilder.create(builder -> builder.group(
                Codec.STRING.fieldOf("sub").forGetter(MUAUser::sub),
                Codec.STRING.fieldOf("nickname").forGetter(MUAUser::nickname),
                Codec.STRING.fieldOf("email").forGetter(MUAUser::email)).apply(builder, MUAUser::new));
        STREAM_CODEC = StreamCodec.composite(
                ByteBufCodecs.STRING_UTF8, MUAUser::sub,
                ByteBufCodecs.STRING_UTF8, MUAUser::nickname,
                ByteBufCodecs.STRING_UTF8, MUAUser::email, MUAUser::new);
    }

    public MUARecord sign(GameProfile profile, Instant expire, Pair<EdECPublicKey, EdECPrivateKey> keys) {
        var keyBytes = Ed25519.serialize(keys.getFirst());
        var signature = Ed25519.sign(keys.getSecond(), expire, Pair.of(profile, this), MUARecord.STREAM_CODEC_PART);
        return new MUARecord(profile, this, List.of(new MUARecord.SignEntry(keyBytes, expire, signature)));
    }
}
