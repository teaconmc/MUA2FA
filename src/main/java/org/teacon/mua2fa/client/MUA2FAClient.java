package org.teacon.mua2fa.client;

import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.event.lifecycle.FMLClientSetupEvent;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import net.neoforged.neoforge.client.event.ScreenEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.data.MUASelector;
import org.teacon.mua2fa.network.RequestForClientRecordPacket;
import org.teacon.mua2fa.network.RequestForClientRefreshPacket;
import org.teacon.mua2fa.network.ResponseToServerCancelPacket;
import org.teacon.mua2fa.network.ResponseToServerRecordPacket;

import javax.annotation.ParametersAreNonnullByDefault;
import java.util.Objects;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
@Mod(value = MUA2FA.ID, dist = Dist.CLIENT)
public final class MUA2FAClient {
    private final ConnectScreenListener listener;

    public MUA2FAClient(IEventBus modEventBus, ModContainer container) {
        var v = container.getModInfo().getVersion();
        this.listener = new ConnectScreenListener("MUA2FA/" + v);
        modEventBus.addListener(FMLClientSetupEvent.class, this::on);
        modEventBus.addListener(RegisterPayloadHandlersEvent.class, this::on);
        NeoForge.EVENT_BUS.addListener(ScreenEvent.Opening.class, this.listener::on);
        NeoForge.EVENT_BUS.addListener(ScreenEvent.Closing.class, this.listener::on);
        NeoForge.EVENT_BUS.addListener(ScreenEvent.Init.Post.class, this.listener::on);
        NeoForge.EVENT_BUS.addListener(ClientTickEvent.Post.class, this.listener::on);
    }

    private void on(FMLClientSetupEvent event) {
        event.enqueueWork(this.listener::load);
        event.enqueueWork(() -> MUASelector.register(((matcher, player) -> false)));
    }

    private void on(RegisterPayloadHandlersEvent event) {
        var registrar = event.registrar(MUA2FA.NETWORK_VERSION).optional();
        registrar.configurationToServer(ResponseToServerRecordPacket.TYPE,
                ResponseToServerRecordPacket.STREAM_CODEC, Objects::hash);
        registrar.configurationToServer(ResponseToServerCancelPacket.TYPE,
                ResponseToServerCancelPacket.STREAM_CODEC, Objects::hash);
        registrar.configurationToClient(RequestForClientRecordPacket.TYPE,
                RequestForClientRecordPacket.STREAM_CODEC, this.listener::handle);
        registrar.configurationToClient(RequestForClientRefreshPacket.TYPE,
                RequestForClientRefreshPacket.STREAM_CODEC, this.listener::handle);
    }
}
