package org.teacon.mua2fa.network;

import io.netty.buffer.ByteBuf;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.data.Ed25519;
import org.teacon.mua2fa.data.HashBase85;
import org.teacon.mua2fa.data.OAuthState;

import javax.annotation.ParametersAreNonnullByDefault;
import java.security.interfaces.EdECPublicKey;
import java.time.Duration;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public record RequestForClientRecordPacket(EdECPublicKey key,
                                           Duration duration, boolean forceRefresh,
                                           String authBaseUri, String recordBaseUri,
                                           OAuthState state) implements CustomPacketPayload {
    public static final Type<RequestForClientRecordPacket> TYPE;
    public static final StreamCodec<ByteBuf, RequestForClientRecordPacket> STREAM_CODEC;

    static {
        TYPE = new Type<>(ResourceLocation.fromNamespaceAndPath(MUA2FA.ID, "request_for_client_record"));
        var publicKeyStreamCodec = HashBase85.ofStreamCodec(256).map(Ed25519::single, Ed25519::serialize);
        var durationStreamCodec = ByteBufCodecs.VAR_LONG.map(Duration::ofMillis, Duration::toMillis);
        STREAM_CODEC = StreamCodec.composite(
                publicKeyStreamCodec, RequestForClientRecordPacket::key,
                durationStreamCodec, RequestForClientRecordPacket::duration,
                ByteBufCodecs.BOOL, RequestForClientRecordPacket::forceRefresh,
                ByteBufCodecs.STRING_UTF8, RequestForClientRecordPacket::authBaseUri,
                ByteBufCodecs.STRING_UTF8, RequestForClientRecordPacket::recordBaseUri,
                OAuthState.STREAM_CODEC, RequestForClientRecordPacket::state, RequestForClientRecordPacket::new);
    }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
