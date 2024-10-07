package org.teacon.mua2fa.server;

import io.netty.channel.epoll.Epoll;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.Util;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.network.ConfigurationTask;
import net.minecraft.server.network.ServerConfigurationPacketListenerImpl;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.lifecycle.FMLDedicatedServerSetupEvent;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.server.ServerStartingEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import net.neoforged.neoforge.event.tick.ServerTickEvent;
import net.neoforged.neoforge.network.configuration.ICustomConfigurationTask;
import net.neoforged.neoforge.network.event.RegisterConfigurationTasksEvent;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.data.MUASelector;
import org.teacon.mua2fa.data.OAuthHttp;
import org.teacon.mua2fa.data.OAuthState;
import org.teacon.mua2fa.network.RequestForClientRecordPacket;
import org.teacon.mua2fa.network.RequestForClientRefreshPacket;
import org.teacon.mua2fa.network.ResponseToServerCancelPacket;
import org.teacon.mua2fa.network.ResponseToServerRecordPacket;

import javax.annotation.ParametersAreNonnullByDefault;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
@Mod(value = MUA2FA.ID, dist = Dist.DEDICATED_SERVER)
public final class MUA2FADedicatedServer {
    private static final ConfigurationTask.Type CONFIGURATION;
    private static final Marker MARKER = MarkerManager.getMarker("Server");

    static {
        CONFIGURATION = new ConfigurationTask.Type(ResourceLocation.fromNamespaceAndPath(MUA2FA.ID, "configuration"));
    }

    private final Map<UUID, ConnectionSession> sessions = new HashMap<>();
    private final Map<UUID, Optional<String>> muaIdentifiers = new HashMap<>();
    private final OAuthHttp server;
    private final String userAgent;
    private final ConfigSpec config;

    public MUA2FADedicatedServer(IEventBus modEventBus, ModContainer container) {
        modEventBus.addListener(RegisterConfigurationTasksEvent.class, this::on);
        modEventBus.addListener(RegisterPayloadHandlersEvent.class, this::on);
        modEventBus.addListener(FMLDedicatedServerSetupEvent.class, this::on);

        NeoForge.EVENT_BUS.addListener(PlayerEvent.PlayerLoggedOutEvent.class, this::on);
        NeoForge.EVENT_BUS.addListener(ServerTickEvent.Post.class, this::on);
        NeoForge.EVENT_BUS.addListener(ServerStartingEvent.class, this::on);
        NeoForge.EVENT_BUS.addListener(ServerStoppingEvent.class, this::on);

        this.config = Util.make(new ConfigSpec(), conf -> container.registerConfig(ModConfig.Type.SERVER, conf));
        this.userAgent = "MUA2FA/" + container.getModInfo().getVersion();
        this.server = new OAuthHttp();
    }

    private void on(RegisterConfigurationTasksEvent event) {
        event.register(new ICustomConfigurationTask() {
            @Override
            public void run(Consumer<CustomPacketPayload> sender) {
                if (event.getListener() instanceof ServerConfigurationPacketListenerImpl conn) {
                    conn.getMainThreadEventLoop().execute(() -> {
                        var now = Instant.now();
                        var profile = conn.getOwner();
                        var config = MUA2FADedicatedServer.this.config;
                        var session = MUA2FADedicatedServer.this.sessions.compute(profile.getId(), (k, v) -> {
                            var deadline = v != null ? v.deadline() : now.plus(OAuthHttp.MUA_REQUEST_COUNTDOWN);
                            return new ConnectionSession(deadline, conn);
                            // the old connection of the player can be garbage collected
                        });
                        var ddl = session.deadline();
                        var key = config.getTokenSignKey();
                        var duration = Duration.between(now, ddl);
                        var u1 = OAuthHttp.auth(config).toString();
                        var u2 = OAuthHttp.record(config).toString();
                        var expire = ddl.plus(OAuthHttp.POLL_INTERVAL);
                        var state = OAuthState.sign(profile.getId(), profile.getName(), expire, key.getSecond());
                        sender.accept(new RequestForClientRecordPacket(key.getFirst(), duration, false, u1, u2, state));
                    });
                }
            }

            @Override
            public Type type() {
                return CONFIGURATION;
            }
        });
    }

    private void on(RegisterPayloadHandlersEvent event) {
        var registrar = event.registrar(MUA2FA.NETWORK_VERSION);
        registrar.configurationToClient(RequestForClientRecordPacket.TYPE,
                RequestForClientRecordPacket.STREAM_CODEC, Objects::hash);
        registrar.configurationToClient(RequestForClientRefreshPacket.TYPE,
                RequestForClientRefreshPacket.STREAM_CODEC, Objects::hash);
        registrar.configurationToServer(ResponseToServerRecordPacket.TYPE,
                ResponseToServerRecordPacket.STREAM_CODEC, this::handle);
        registrar.configurationToServer(ResponseToServerCancelPacket.TYPE,
                ResponseToServerCancelPacket.STREAM_CODEC, this::handle);
    }

    private void on(FMLDedicatedServerSetupEvent event) {
        event.enqueueWork(() -> MUASelector.register(((matcher, player) -> {
            var identifier = this.muaIdentifiers.getOrDefault(player.getUUID(), Optional.empty());
            return identifier.filter(matcher).isPresent();
        })));
    }

    private void on(ServerStartingEvent event) {
        var internal = this.config.getServerInternalAddress();
        if (internal.getPort() > 0) {
            var server = event.getServer();
            this.server.start(Epoll.isAvailable() && server.isEpollEnabled(), this.config, this.userAgent);
        }
    }

    private void on(ServerTickEvent.Post event) {
        this.sessions.entrySet().removeIf(entry -> {
            var session = entry.getValue();
            // allow additional 30 seconds for network delays
            if (session.deadline().plus(OAuthHttp.NETWORK_TOLERANCE).isBefore(Instant.now())) {
                var profile = session.conn().getOwner();
                MUA2FA.LOGGER.info(MARKER, "Player {} ({}) time out", profile.getName(), profile.getId());
                session.conn().disconnect(Component.translatable("disconnect.timeout"));
                // the connection of the player can be garbage collected
                return true;
            }
            return false;
        });
    }

    private void on(PlayerEvent.PlayerLoggedOutEvent event) {
        var player = event.getEntity();
        // the connection of the player can be garbage collected
        this.sessions.remove(player.getUUID());
        this.muaIdentifiers.remove(player.getUUID());
    }

    private void on(ServerStoppingEvent event) {
        this.server.close();
        // all the connections can be garbage collected
        this.sessions.clear();
        this.muaIdentifiers.clear();
    }

    private void handle(ResponseToServerRecordPacket packet, IPayloadContext context) {
        var record = packet.record();
        var profile = record.getProfile();
        var key = this.config.getTokenSignKey();
        if (record.verify(profile, key.getFirst()).test(Instant.now())) {
            var profileId = profile.getId();
            this.muaIdentifiers.put(profileId, Optional.of(record.getUser().sub()));
            context.reply(new RequestForClientRefreshPacket(record));
            context.finishCurrentTask(CONFIGURATION);
            // the connection of the player can be garbage collected
            this.sessions.remove(profileId);
        } else {
            var profileId = profile.getId();
            var session = this.sessions.get(profileId);
            if (session != null) {
                var now = Instant.now();
                var ddl = session.deadline();
                var duration = Duration.between(now, ddl);
                var u1 = OAuthHttp.auth(this.config).toString();
                var u2 = OAuthHttp.record(this.config).toString();
                var expire = ddl.plus(OAuthHttp.NETWORK_TOLERANCE);
                var state = OAuthState.sign(profile.getId(), profile.getName(), expire, key.getSecond());
                context.reply(new RequestForClientRecordPacket(key.getFirst(), duration, true, u1, u2, state));
            } else {
                context.disconnect(Component.translatable("disconnect.timeout"));
                // the connection of the player can be garbage collected
                this.sessions.remove(profileId);
            }
        }
    }

    private void handle(ResponseToServerCancelPacket packet, IPayloadContext context) {
        var state = packet.state();
        if (!state.verify(this.config.getTokenSignKey().getFirst()).test(Instant.now())) {
            context.disconnect(Component.translatable("disconnect.timeout"));
            // the connection of the player can be garbage collected
            this.sessions.remove(state.id());
        } else if (this.config.getMUARequireUnionAuth()) {
            context.disconnect(Component.translatable("multiplayer.disconnect.not_whitelisted"));
            // the connection of the player can be garbage collected
            this.sessions.remove(state.id());
        } else {
            this.muaIdentifiers.put(state.id(), Optional.empty());
            context.finishCurrentTask(CONFIGURATION);
            // the connection of the player can be garbage collected
            this.sessions.remove(state.id());
        }
    }
}
