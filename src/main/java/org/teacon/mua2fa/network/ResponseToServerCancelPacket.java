package org.teacon.mua2fa.network;

import io.netty.buffer.ByteBuf;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.data.OAuthState;

import javax.annotation.ParametersAreNonnullByDefault;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public record ResponseToServerCancelPacket(OAuthState state) implements CustomPacketPayload {
    public static final Type<ResponseToServerCancelPacket> TYPE;
    public static final StreamCodec<ByteBuf, ResponseToServerCancelPacket> STREAM_CODEC;

    static {
        TYPE = new Type<>(ResourceLocation.fromNamespaceAndPath(MUA2FA.ID, "response_to_server_cancel"));
        STREAM_CODEC = OAuthState.STREAM_CODEC
                .map(ResponseToServerCancelPacket::new, ResponseToServerCancelPacket::state);
    }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
