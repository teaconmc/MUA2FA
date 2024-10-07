package org.teacon.mua2fa.client;

import com.mojang.datafixers.util.Pair;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.Util;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.components.AbstractButton;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.events.GuiEventListener;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.resources.language.I18n;
import net.minecraft.nbt.CompoundTag;
import net.minecraft.nbt.NbtIo;
import net.minecraft.nbt.NbtOps;
import net.minecraft.network.chat.Component;
import net.neoforged.neoforge.client.event.ClientTickEvent;
import net.neoforged.neoforge.client.event.ScreenEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import org.apache.commons.lang3.function.BooleanConsumer;
import org.apache.commons.lang3.stream.Streams;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.joml.Vector2i;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.data.MUARecord;
import org.teacon.mua2fa.data.OAuthHttp;
import org.teacon.mua2fa.data.OAuthState;
import org.teacon.mua2fa.network.RequestForClientRecordPacket;
import org.teacon.mua2fa.network.RequestForClientRefreshPacket;
import org.teacon.mua2fa.network.ResponseToServerCancelPacket;
import org.teacon.mua2fa.network.ResponseToServerRecordPacket;
import reactor.core.Disposable;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class ConnectionScreenListener {
    private static final Marker MARKER = MarkerManager.getMarker("Connection");

    private @Nullable URI authUri;
    private @Nullable URI recordUri;
    private @Nullable MUARecord record;
    private @Nullable Disposable recordPolls;
    private @Nullable Instant muaRequestExpire;
    private Consumer<Component> updateConnectionMessage = Objects::hash;

    private final Buttons buttons;
    private final String userAgent;

    public ConnectionScreenListener(String userAgent) {
        this.userAgent = userAgent;
        this.buttons = new Buttons();
    }

    public void on(ScreenEvent.Opening event) {
        if (event.getScreen() instanceof ConnectScreen screen) {
            this.buttons.open(this::click);
            this.updateConnectionMessage = screen::updateStatus;
        }
    }

    public void on(ScreenEvent.Closing event) {
        if (event.getScreen() instanceof ConnectScreen) {
            this.buttons.close();
            this.updateConnectionMessage = Objects::hash;
        }
    }

    public void on(ScreenEvent.Init.Post event) {
        if (event.getScreen() instanceof ConnectScreen screen) {
            this.buttons.init(new Vector2i(screen.width, screen.height), event.getListenersList(), event::addListener);
        }
    }

    public void on(ClientTickEvent.Post event) {
        Objects.requireNonNull(event);
        if (this.muaRequestExpire != null) {
            var diff = Duration.between(Instant.now(), this.muaRequestExpire);
            if (diff.isPositive()) {
                var diffText = "%02d:%02d".formatted(diff.toMinutes(), diff.toSecondsPart());
                this.updateConnectionMessage.accept(Component.translatable("mua2fa.mua_request", diffText));
            } else {
                this.buttons.cancel();
            }
        }
    }

    public void click(boolean login, OAuthState state, IPayloadContext context) {
        if (login && this.authUri != null) {
            if (this.recordUri != null && this.recordPolls == null) {
                var poll = OAuthHttp.poll(this.recordUri, this.userAgent, Duration.ofSeconds(3L));
                this.recordPolls = poll.subscribe(record -> context.enqueueWork(() -> {
                    MUA2FA.LOGGER.info(MARKER, "Fetched the record of the player");
                    context.reply(new ResponseToServerRecordPacket(record));
                }));
            }
            Util.getPlatform().openUri(this.authUri);
        } else {
            this.buttons.hide();
            this.buttons.close();
            this.muaRequestExpire = null;
            if (this.recordPolls != null) {
                this.recordPolls.dispose();
                this.recordPolls = null;
            }
            context.reply(new ResponseToServerCancelPacket(state));
            this.updateConnectionMessage.accept(Component.translatable("connect.joining"));
        }
    }

    public void handle(RequestForClientRecordPacket packet, IPayloadContext context) {
        context.enqueueWork(() -> {
            var profile = Minecraft.getInstance().getGameProfile();
            if (this.record != null) {
                var bypass = !packet.forceRefresh() && this.record.verify(profile, packet.key()).test(Instant.now());
                if (bypass) {
                    context.reply(new ResponseToServerRecordPacket(this.record));
                    return;
                }
            }
            this.muaRequestExpire = Instant.now().plus(packet.duration());
            var cancelHint = I18n.get("mua2fa.cancel_title") + "\n" + I18n.get("mua2fa.cancel_subtitle");
            var completeHint = I18n.get("mua2fa.complete_title") + "\n" + I18n.get("mua2fa.complete_subtitle");
            var state = packet.state().with(cancelHint, completeHint);
            try {
                var recordBuilder = new URIBuilder(Util.parseAndValidateUntrustedUri(packet.recordBaseUri()));
                var authBuilder = new URIBuilder(Util.parseAndValidateUntrustedUri(packet.authBaseUri()));
                this.recordUri = recordBuilder.addParameter("state", state.toString()).build();
                this.authUri = authBuilder.addParameter("state", state.toString()).build();
            } catch (URISyntaxException e) {
                MUA2FA.LOGGER.warn(MARKER, "Invalid auth uri: {}", packet.authBaseUri(), e);
                this.recordPolls = null;
                this.authUri = null;
            }
            this.buttons.show(state, context);
        });
    }

    public void handle(RequestForClientRefreshPacket packet, IPayloadContext context) {
        context.enqueueWork(() -> {
            this.record = this.record == null ? packet.record() : this.record.refresh(packet.record());
            this.save();
            this.buttons.hide();
            this.buttons.close();
            this.muaRequestExpire = null;
            if (this.recordPolls != null) {
                this.recordPolls.dispose();
                this.recordPolls = null;
            }
            var message = Component.translatable("connect.joining");
            if (this.record != null) {
                var user = this.record.getUser();
                message = Component.translatable("mua2fa.mua_info", message, user.nickname());
            }
            this.updateConnectionMessage.accept(message);
        });
    }

    public void load() {
        try {
            var gameDir = Minecraft.getInstance().gameDirectory.toPath();
            var data = NbtIo.read(gameDir.resolve("mua2fa.dat"));
            if (data != null && !data.isEmpty()) {
                var record = MUARecord.CODEC.decode(NbtOps.INSTANCE, data).getOrThrow(IOException::new);
                this.record = record.getFirst();
            } else {
                this.record = null;
            }
        } catch (IOException e) {
            MUA2FA.LOGGER.warn(MARKER, "Failed to load mua2fa data", e);
        }
    }

    public void save() {
        try {
            var gameDir = Minecraft.getInstance().gameDirectory.toPath();
            var tmp = Files.createTempFile(gameDir, "mua2fa", ".dat");
            var data = new CompoundTag();
            if (this.record != null) {
                var filtered = this.record.filter(Instant.now());
                data = (CompoundTag) MUARecord.CODEC.encode(filtered, NbtOps.INSTANCE, data).getOrThrow();
            }
            NbtIo.write(data, tmp);
            Util.safeReplaceFile(gameDir.resolve("mua2fa.dat"), tmp, gameDir.resolve("mua2fa.dat_old"));
        } catch (IOException | IllegalStateException | ClassCastException e) {
            MUA2FA.LOGGER.warn(MARKER, "Failed to save mua2fa data", e);
        }
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    private static final class Buttons implements Closeable {
        private static final Component MUA = Component.translatable("mua2fa.login_as_mua");
        private static final Component NOT_MUA = Component.translatable("mua2fa.not_login_as_mua");

        private BooleanConsumer click = BooleanConsumer.nop();
        private @Nullable Pair<OAuthState, IPayloadContext> connection;

        private final Button[] additional = new Button[2];
        private final BitSet existingVisible = new BitSet(1);
        private final List<AbstractButton> existing = new ArrayList<>(1);

        public void open(ButtonsCallback callback) {
            this.connection = null;
            this.click = login -> {
                if (this.connection != null) {
                    callback.on(login, this.connection.getFirst(), this.connection.getSecond());
                }
            };
        }

        public void init(Vector2i dimension, List<GuiEventListener> listeners, Consumer<GuiEventListener> collector) {
            this.existing.clear();
            this.existingVisible.clear();
            var x0 = dimension.x / 2 - 100;
            var y0 = dimension.y / 4 + 96 + 12;
            var y1 = dimension.y / 4 + 120 + 12;
            this.additional[0] = Button.builder(MUA, b -> this.click.accept(true)).bounds(x0, y0, 200, 20).build();
            this.additional[1] = Button.builder(NOT_MUA, b -> this.click.accept(false)).bounds(x0, y1, 200, 20).build();
            collector.accept(this.additional[0]);
            collector.accept(this.additional[1]);
            this.additional[0].visible = this.additional[1].visible = false;
            Streams.instancesOf(AbstractButton.class, listeners).forEach(this.existing::add);
        }

        public void show(OAuthState state, IPayloadContext context) {
            this.connection = Pair.of(state, context);
            for (var i = 0; i < this.existing.size(); i++) {
                this.existingVisible.set(i, this.existing.get(i).visible);
                this.existing.get(i).visible = false;
            }
            this.additional[0].visible = this.additional[1].visible = true;
        }

        public void hide() {
            if (this.connection != null) {
                for (var i = 0; i < this.existing.size(); i++) {
                    this.existing.get(i).visible = this.existingVisible.get(i);
                }
                this.connection = null;
                this.existingVisible.clear();
                this.additional[0].visible = this.additional[1].visible = false;
            }
        }

        public void cancel() {
            this.click.accept(false);
        }

        @Override
        public void close() {
            this.existing.clear();
            this.connection = null;
            this.existingVisible.clear();
            this.click = BooleanConsumer.nop();
            Arrays.fill(this.additional, null);
        }
    }

    @FunctionalInterface
    @ParametersAreNonnullByDefault
    public interface ButtonsCallback {
        void on(boolean login, OAuthState state, IPayloadContext context);
    }
}
