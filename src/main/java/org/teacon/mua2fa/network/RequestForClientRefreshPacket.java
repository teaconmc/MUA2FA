package org.teacon.mua2fa.network;

import io.netty.buffer.ByteBuf;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.data.MUARecord;

import javax.annotation.ParametersAreNonnullByDefault;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public record RequestForClientRefreshPacket(MUARecord record) implements CustomPacketPayload {
    public static final Type<RequestForClientRefreshPacket> TYPE;
    public static final StreamCodec<ByteBuf, RequestForClientRefreshPacket> STREAM_CODEC;

    static {
        TYPE = new Type<>(ResourceLocation.fromNamespaceAndPath(MUA2FA.ID, "request_for_client_refresh"));
        STREAM_CODEC = MUARecord.STREAM_CODEC
                .map(RequestForClientRefreshPacket::new, RequestForClientRefreshPacket::record);
    }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
