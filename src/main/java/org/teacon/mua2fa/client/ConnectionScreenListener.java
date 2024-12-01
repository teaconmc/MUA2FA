package org.teacon.mua2fa.client;

import com.google.common.base.Preconditions;
import com.mojang.datafixers.util.Either;
import com.mojang.serialization.Codec;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class ConnectionScreenListener {
    private static final Marker MARKER = MarkerManager.getMarker("Connection");

    private static final Codec<Either<MUARecord, MUAEmptyState>> CODEC;

    static {
        CODEC = Codec.mapEither(MUARecord.MAP_CODEC,
                MUAEmptyState.CODEC.optionalFieldOf("state", MUAEmptyState.INIT)).codec();
    }

    private @Nullable URI authUri;
    private @Nullable URI recordUri;
    private @Nullable Disposable recordPolls;
    private @Nullable Instant muaRequestExpire;
    private Consumer<Component> updateConnectionMessage = Objects::hash;
    private Either<MUARecord, MUAEmptyState> data = Either.right(MUAEmptyState.INIT);

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

    public void click(int index, OAuthState state, IPayloadContext context) {
        if (index == Buttons.AUTH && this.authUri != null) {
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
            if (index == Buttons.SKIP_FOREVER) {
                this.data = Either.right(MUAEmptyState.HIDE_FOREVER);
                this.save();
            } else {
                this.data = this.data.mapRight(e -> MUAEmptyState.SHOW_IF_NECESSARY);
                this.save();
            }
            context.reply(new ResponseToServerCancelPacket(state));
            this.updateConnectionMessage.accept(Component.translatable("connect.joining"));
        }
    }

    public void handle(RequestForClientRecordPacket packet, IPayloadContext context) {
        context.enqueueWork(() -> {
            var profile = Minecraft.getInstance().getGameProfile();
            // append hints to the oauth state
            var cancelHint = I18n.get("mua2fa.cancel_title") + "\n" + I18n.get("mua2fa.cancel_subtitle");
            var completeHint = I18n.get("mua2fa.complete_title") + "\n" + I18n.get("mua2fa.complete_subtitle");
            var state = packet.state().with(cancelHint, completeHint);
            // bypass if the record is valid now
            var recordToBypass = this.data.left().filter(record -> {
                if (packet.forceRefresh()) {
                    return false; // bypassing is disabled if the packet from the server requires this
                }
                return record.verify(profile, packet.key()).test(Instant.now());
            });
            if (recordToBypass.isPresent()) {
                context.reply(new ResponseToServerRecordPacket(recordToBypass.get()));
                return;
            }
            // bypass if the record is empty and hide forever is chosen
            var emptyToBypass = this.data.right().filter(MUAEmptyState.HIDE_FOREVER::equals);
            if (emptyToBypass.isPresent()) {
                context.reply(new ResponseToServerCancelPacket(state));
                return;
            }
            // set the expiration timestamp and urls
            this.muaRequestExpire = Instant.now().plus(packet.duration());
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
            // show the mua request screen
            var includeHideForever = !this.data.right().orElse(MUAEmptyState.INIT).equals(MUAEmptyState.INIT);
            this.buttons.show(state, includeHideForever, context);
        });
    }

    public void handle(RequestForClientRefreshPacket packet, IPayloadContext context) {
        context.enqueueWork(() -> {
            this.data = Either.left(this.data.map(r -> r.refresh(packet.record()), e -> packet.record()));
            this.save();
            this.buttons.hide();
            this.buttons.close();
            this.muaRequestExpire = null;
            if (this.recordPolls != null) {
                this.recordPolls.dispose();
                this.recordPolls = null;
            }
            var message = Component.translatable("connect.joining");
            var user = this.data.left().map(MUARecord::getUser);
            if (user.isPresent()) {
                message = Component.translatable("mua2fa.mua_info", message, user.get().nickname());
            }
            this.updateConnectionMessage.accept(message);
        });
    }

    public void load() {
        try {
            var gameDir = Minecraft.getInstance().gameDirectory.toPath();
            var data = Objects.requireNonNullElse(NbtIo.read(gameDir.resolve("mua2fa.dat")), new CompoundTag());
            this.data = CODEC.decode(NbtOps.INSTANCE, data).getOrThrow(IOException::new).getFirst();
        } catch (IOException e) {
            MUA2FA.LOGGER.warn(MARKER, "Failed to load mua2fa data", e);
        }
    }

    public void save() {
        try {
            var gameDir = Minecraft.getInstance().gameDirectory.toPath();
            var tmpPath = Files.createTempFile(gameDir, "mua2fa", ".dat");
            var filtered = this.data.mapLeft(r -> r.filter(Instant.now()));
            var result = CODEC.encode(filtered, NbtOps.INSTANCE, new CompoundTag());
            NbtIo.write((CompoundTag) result.getOrThrow(), tmpPath);
            Util.safeReplaceFile(gameDir.resolve("mua2fa.dat"), tmpPath, gameDir.resolve("mua2fa.dat_old"));
        } catch (IOException | IllegalStateException | ClassCastException e) {
            MUA2FA.LOGGER.warn(MARKER, "Failed to save mua2fa data", e);
        }
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    private record MUAClientSession(OAuthState state, boolean includeHideForever, IPayloadContext context) {
        // nothing here
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    private static final class Buttons implements Closeable {
        public static final int AUTH = 0, SKIP = 1, SKIP_FOREVER = 2, SIZE = 3;

        private static final Component MUA = Component.translatable("mua2fa.login_as_mua");
        private static final Component NOT_MUA = Component.translatable("mua2fa.not_login_as_mua");
        private static final Component NOT_MUA_FOREVER = Component.translatable("mua2fa.not_login_as_mua_forever");

        private @Nullable MUAClientSession session;
        private IntConsumer click = i -> Preconditions.checkState(i >= 0 && i <= SIZE);

        private final Button[] appended = new Button[SIZE];
        private final List<ButtonExisting> existing = new ArrayList<>(1);

        public void open(ButtonsCallback callback) {
            this.session = null;
            this.click = index -> {
                if (this.session != null) {
                    callback.on(index, this.session.state(), this.session.context());
                }
            };
        }

        public void init(Vector2i dimension, List<GuiEventListener> listeners, Consumer<GuiEventListener> collector) {
            this.existing.clear();
            var x0 = dimension.x / 2 - 100;
            var y0 = dimension.y / 4 + 108;
            var y1 = dimension.y / 4 + 132;
            var y2 = dimension.y / 4 + 156;
            collector.accept(this.appended[AUTH] = Button.builder(MUA,
                    button -> this.click.accept(AUTH)).bounds(x0, y0, 200, 20).build());
            collector.accept(this.appended[SKIP] = Button.builder(NOT_MUA,
                    button -> this.click.accept(SKIP)).bounds(x0, y1, 200, 20).build());
            collector.accept(this.appended[SKIP_FOREVER] = Button.builder(NOT_MUA_FOREVER,
                    button -> this.click.accept(SKIP_FOREVER)).bounds(x0, y2, 200, 20).build());
            Streams.instancesOf(AbstractButton.class, listeners).map(ButtonExisting::new).forEach(this.existing::add);
            if (this.session == null) {
                this.appended[AUTH].visible = false;
                this.appended[SKIP].visible = false;
                this.appended[SKIP_FOREVER].visible = false;
            } else {
                this.existing.replaceAll(ButtonExisting::hide);
                this.appended[AUTH].visible = true;
                this.appended[SKIP].visible = true;
                this.appended[SKIP_FOREVER].visible = this.session.includeHideForever();
            }
        }

        public void show(OAuthState state, boolean includeHideForever, IPayloadContext context) {
            if (this.session == null) {
                this.session = new MUAClientSession(state, includeHideForever, context);
                this.existing.replaceAll(ButtonExisting::hide);
                this.appended[AUTH].visible = true;
                this.appended[SKIP].visible = true;
                this.appended[SKIP_FOREVER].visible = includeHideForever;
            }
        }

        public void hide() {
            if (this.session != null) {
                this.session = null;
                this.existing.replaceAll(ButtonExisting::show);
                this.appended[AUTH].visible = false;
                this.appended[SKIP].visible = false;
                this.appended[SKIP_FOREVER].visible = false;
            }
        }

        public void cancel() {
            this.click.accept(SKIP);
        }

        @Override
        public void close() {
            this.session = null;
            this.existing.clear();
            this.click = i -> Preconditions.checkState(i >= 0 && i <= SIZE);
            this.appended[AUTH] = this.appended[SKIP] = this.appended[SKIP_FOREVER] = null;
        }
    }

    @FieldsAreNonnullByDefault
    @MethodsReturnNonnullByDefault
    @ParametersAreNonnullByDefault
    private record ButtonExisting(AbstractButton button, boolean visible) {
        public ButtonExisting(AbstractButton button) {
            this(button, false);
        }

        public ButtonExisting hide() {
            var result = new ButtonExisting(this.button, this.button.visible);
            this.button.visible = false;
            return result;
        }

        public ButtonExisting show() {
            var result = new ButtonExisting(this.button, false);
            this.button.visible = this.visible;
            return result;
        }
    }

    @FunctionalInterface
    @ParametersAreNonnullByDefault
    public interface ButtonsCallback {
        void on(int index, OAuthState state, IPayloadContext context);
    }
}
