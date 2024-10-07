package org.teacon.mua2fa.data;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;
import com.mojang.authlib.GameProfile;
import com.mojang.datafixers.util.Pair;
import com.mojang.serialization.Codec;
import com.mojang.serialization.codecs.RecordCodecBuilder;
import io.netty.buffer.ByteBuf;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.util.ExtraCodecs;

import javax.annotation.ParametersAreNonnullByDefault;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.function.Predicate;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class MUARecord {
    public static final Codec<MUARecord> CODEC;
    public static final StreamCodec<ByteBuf, MUARecord> STREAM_CODEC;
    public static final StreamCodec<ByteBuf, Pair<GameProfile, User>> STREAM_CODEC_PART;

    static {
        CODEC = RecordCodecBuilder.create(builder -> builder.group(
                        RecordCodecBuilder.<GameProfile>mapCodec(b -> b.group(
                                        UUIDUtil.AUTHLIB_CODEC.fieldOf("id").forGetter(GameProfile::getId),
                                        ExtraCodecs.PLAYER_NAME.fieldOf("name").forGetter(GameProfile::getName))
                                .apply(b, GameProfile::new)).forGetter(MUARecord::getProfile),
                        User.CODEC.fieldOf("mua").forGetter(MUARecord::getUser),
                        Codec.list(SignEntry.CODEC).fieldOf("signatures").forGetter(MUARecord::getSignatures))
                .apply(builder, MUARecord::new));
        STREAM_CODEC = StreamCodec.composite(
                ByteBufCodecs.GAME_PROFILE, MUARecord::getProfile, User.STREAM_CODEC, MUARecord::getUser,
                SignEntry.STREAM_CODEC.apply(ByteBufCodecs.list()), MUARecord::getSignatures, MUARecord::new);
        STREAM_CODEC_PART = StreamCodec.composite(
                ByteBufCodecs.GAME_PROFILE, Pair::getFirst, User.STREAM_CODEC, Pair::getSecond, Pair::of);
    }

    private final User user;
    private final GameProfile profile;
    private final List<SignEntry> signatures;

    public MUARecord(GameProfile profile, User user, Collection<? extends SignEntry> signatures) {
        this.user = user;
        this.profile = profile;
        this.signatures = List.copyOf(signatures);
    }

    public User getUser() {
        return this.user;
    }

    public GameProfile getProfile() {
        return this.profile;
    }

    public List<SignEntry> getSignatures() {
        return this.signatures;
    }

    public Predicate<Instant> verify(GameProfile profile, EdECPublicKey key) {
        if (!this.profile.equals(profile)) {
            return Predicates.alwaysFalse();
        }
        var keyBytes = Ed25519.serialize(key);
        var pair = Pair.of(this.profile, this.user);
        return i -> this.signatures.stream().anyMatch(s -> {
            if (s.getKeyBytes().equals(keyBytes)) {
                return Ed25519.verify(key, s.getExpireAt(), s.getSignature(), pair, STREAM_CODEC_PART).test(i);
            }
            return false;
        });
    }

    public MUARecord refresh(MUARecord newOne) {
        if (newOne.getProfile().equals(this.profile) && newOne.getUser().equals(this.user)) {
            var builder = ImmutableList.<SignEntry>builder();
            builder.addAll(this.signatures).addAll(newOne.getSignatures());
            return new MUARecord(this.profile, this.user, builder.build());
        }
        return newOne;
    }

    public MUARecord filter(Instant now) {
        var pair = Pair.of(this.profile, this.user);
        var filtered = new LinkedHashMap<HashCode, SignEntry>(this.signatures.size());
        for (var e : this.signatures) {
            filtered.compute(e.getKeyBytes(), (k, v) -> {
                if (!Ed25519.verify(e.getKey(), e.getExpireAt(), e.getSignature(), pair, STREAM_CODEC_PART).test(now)) {
                    return v;
                }
                if (v != null && v.getExpireAt().isAfter(e.getExpireAt())) {
                    return v;
                }
                return e;
            });
        }
        var signatures = filtered.size() == this.signatures.size() ? this.signatures : filtered.values();
        return new MUARecord(this.profile, this.user, signatures);
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    public static final class SignEntry {
        public static final Codec<SignEntry> CODEC;
        public static final StreamCodec<ByteBuf, SignEntry> STREAM_CODEC;

        static {
            var instantCodec = Codec.LONG.xmap(Instant::ofEpochSecond, Instant::getEpochSecond);
            CODEC = RecordCodecBuilder.create(builder -> builder.group(
                            HashBase85.CODEC.fieldOf("key").forGetter(SignEntry::getKeyBytes),
                            instantCodec.fieldOf("expire_at").forGetter(SignEntry::getExpireAt),
                            HashBase85.CODEC.fieldOf("signature").forGetter(SignEntry::getSignature))
                    .apply(builder, SignEntry::new));
            var instantStreamCodec = ByteBufCodecs.VAR_LONG.map(Instant::ofEpochSecond, Instant::getEpochSecond);
            STREAM_CODEC = StreamCodec.composite(
                    HashBase85.ofStreamCodec(256), SignEntry::getKeyBytes, instantStreamCodec, SignEntry::getExpireAt,
                    HashBase85.ofStreamCodec(512), SignEntry::getSignature, SignEntry::new);
        }

        private final HashCode keyBytes;
        private final EdECPublicKey key;
        private final Instant expireAt;
        private final HashCode signature;

        public SignEntry(HashCode keyBytes, Instant expireAt, HashCode signature) {
            Preconditions.checkArgument(keyBytes.bits() == 256);
            this.keyBytes = keyBytes;
            this.key = Ed25519.single(keyBytes);
            Preconditions.checkArgument(expireAt.isAfter(Instant.EPOCH));
            this.expireAt = expireAt.truncatedTo(ChronoUnit.SECONDS);
            Preconditions.checkArgument(signature.bits() == 512);
            this.signature = signature;
        }

        public HashCode getKeyBytes() {
            return this.keyBytes;
        }

        public EdECPublicKey getKey() {
            return this.key;
        }

        public Instant getExpireAt() {
            return this.expireAt;
        }

        public HashCode getSignature() {
            return this.signature;
        }
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    public record User(String sub, String nickname, String email) {
        public static final Codec<User> CODEC;
        public static final StreamCodec<ByteBuf, User> STREAM_CODEC;

        static {
            CODEC = RecordCodecBuilder.create(builder -> builder.group(
                    Codec.STRING.fieldOf("sub").forGetter(User::sub),
                    Codec.STRING.fieldOf("nickname").forGetter(User::nickname),
                    Codec.STRING.fieldOf("email").forGetter(User::email)).apply(builder, User::new));
            STREAM_CODEC = StreamCodec.composite(
                    ByteBufCodecs.STRING_UTF8, User::sub,
                    ByteBufCodecs.STRING_UTF8, User::nickname,
                    ByteBufCodecs.STRING_UTF8, User::email, User::new);
        }

        public MUARecord sign(GameProfile profile, Instant expire, Pair<EdECPublicKey, EdECPrivateKey> keys) {
            var keyBytes = Ed25519.serialize(keys.getFirst());
            var signature = Ed25519.sign(keys.getSecond(), expire, Pair.of(profile, this), STREAM_CODEC_PART);
            return new MUARecord(profile, this, List.of(new SignEntry(keyBytes, expire, signature)));
        }
    }
}
