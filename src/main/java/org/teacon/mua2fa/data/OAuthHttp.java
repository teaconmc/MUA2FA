package org.teacon.mua2fa.data;

import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.gson.JsonObject;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import com.mojang.authlib.GameProfile;
import com.mojang.datafixers.util.Pair;
import com.mojang.serialization.DataResult;
import com.mojang.serialization.JsonOps;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.codec.http.QueryStringEncoder;
import net.minecraft.FieldsAreNonnullByDefault;
import net.minecraft.MethodsReturnNonnullByDefault;
import net.minecraft.Util;
import net.minecraft.util.GsonHelper;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.teacon.mua2fa.MUA2FA;
import org.teacon.mua2fa.server.ConfigSpec;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import reactor.netty.ByteBufFlux;
import reactor.netty.ByteBufMono;
import reactor.netty.DisposableServer;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientResponse;
import reactor.netty.http.server.HttpServer;

import javax.annotation.ParametersAreNonnullByDefault;
import java.io.Closeable;
import java.io.StringReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static net.minecraft.server.network.ServerConnectionListener.SERVER_EPOLL_EVENT_GROUP;
import static net.minecraft.server.network.ServerConnectionListener.SERVER_EVENT_GROUP;

@FieldsAreNonnullByDefault
@MethodsReturnNonnullByDefault
@ParametersAreNonnullByDefault
public final class OAuthHttp implements Closeable {
    public static final Duration POLL_INTERVAL = Duration.ofSeconds(5L);
    public static final Duration NETWORK_TOLERANCE = Duration.ofSeconds(30L);
    public static final Duration MUA_REQUEST_COUNTDOWN = Duration.ofSeconds(180L);

    private static final Marker MARKER = MarkerManager.getMarker("OAuth");

    private static final String STARTING = "Starting oauth http server ...";
    private static final String STARTED = "Started oauth http server at {}.";
    private static final String STOPPING = "Stopping oauth http server at {} ...";
    private static final String STOPPED = "Stopped oauth http server.";
    private static final String HTML = """
            <!doctype html><html><head><meta charset="utf-8"><meta name="viewport"
            content="width=device-width,initial-scale=1"><title>MUA2FA</title></head>
            <body><pre style="height:88vh;font-size:4vh;display:flex;align-items:center;
            justify-content:center;text-align:center;color:%s">%s</pre></body></html>""";

    private static final Scheduler IO_SCHEDULER = Schedulers.fromExecutor(Util.ioPool());

    private final AtomicReference<DisposableServer> server = new AtomicReference<>();
    private final Sinks.Many<MUARecord.User> records = Sinks.many().replay().limit(NETWORK_TOLERANCE, IO_SCHEDULER);

    private Mono<JsonObject> json(HttpClientResponse res, ByteBufMono body) {
        return body.asString().flatMap(content -> Mono.fromCallable(() -> {
            Preconditions.checkArgument(res.status().code() == 200);
            try (var reader = new JsonReader(new StringReader(content))) {
                return Streams.parse(reader).getAsJsonObject();
            }
        }));
    }

    public static URI auth(ConfigSpec conf) {
        var relative = FilenameUtils.getName(conf.getServerExternalUri().getPath());
        return conf.getServerExternalUri().resolve(StringUtils.defaultIfEmpty(relative, ".") + "/redirect");
    }

    public static URI record(ConfigSpec conf) {
        var relative = FilenameUtils.getName(conf.getServerExternalUri().getPath());
        return conf.getServerExternalUri().resolve(StringUtils.defaultIfEmpty(relative, ".") + "/record");
    }

    public static Mono<MUARecord> poll(URI recordUri, String ua, Duration interval) {
        var client = HttpClient.create().headers(headers -> {
            headers.add(HttpHeaderNames.ACCEPT, HttpHeaderValues.APPLICATION_JSON);
            headers.add(HttpHeaderNames.USER_AGENT, ua);
        });
        var single = client.get().uri(recordUri.toString()).responseSingle((res, mono) -> {
            var json = mono.asString(StandardCharsets.UTF_8).map(GsonHelper::parse);
            var result = json.map(o -> MUARecord.CODEC.decode(JsonOps.INSTANCE, o));
            return result.map(DataResult::getOrThrow).map(Pair::getFirst);
        });
        return Mono.zip(Mono.delay(interval), single, (a, b) -> b).retry();
    }

    public void start(boolean epoll, ConfigSpec conf, String ua) {
        var addr = conf.getServerInternalAddress();
        var runOn = epoll ? SERVER_EPOLL_EVENT_GROUP.get() : SERVER_EVENT_GROUP.get();
        var server = HttpServer.create().runOn(runOn).host(addr.getHost()).port(addr.getPort()).route(routes -> {
            routes.get("/record", (req, res) -> {
                var dec = new QueryStringDecoder(req.uri());
                var decParams = dec.parameters();
                var state = OAuthState.fromString(Iterables.getOnlyElement(decParams.getOrDefault("state", List.of())));
                var fallback = Mono.<String>error(() -> new IllegalArgumentException("time out"));
                var users = this.records.asFlux().take(POLL_INTERVAL).flatMap(user -> {
                    var now = OffsetDateTime.now();
                    var key = conf.getTokenSignKey();
                    if (state.verify(key.getFirst()).test(now.toInstant())) {
                        var expire = now.plus(conf.getTokenValidityPeriod());
                        var profile = new GameProfile(state.id(), state.name());
                        var record = user.sign(profile, expire.toInstant(), key);
                        var result = MUARecord.CODEC.encodeStart(JsonOps.INSTANCE, record);
                        return Mono.just(GsonHelper.toStableString(result.getOrThrow()));
                    }
                    return Mono.empty();
                });
                return users.next().switchIfEmpty(fallback).flatMap(s -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
                    MUA2FA.LOGGER.info(MARKER, "Giving the signed record for player {} ...", state.name());
                    return header.sendString(Mono.just(s)).then();
                }).onErrorResume(e -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
                    MUA2FA.LOGGER.info(MARKER, "No suitable record found for player {}, replying ...", state.name());
                    MUA2FA.LOGGER.debug(MARKER, "No suitable record found for player: {}", e.getMessage(), e);
                    return header.status(404).sendString(Mono.just("{\"error\":\"not found\"}")).then();
                });
            });
            routes.get("/redirect", (req, res) -> {
                var dec = new QueryStringDecoder(req.uri());
                var decParams = dec.parameters();
                var state = OAuthState.fromString(Iterables.getOnlyElement(decParams.getOrDefault("state", List.of())));
                var enc = new QueryStringEncoder("/api/union/oauth2/authorize");
                enc.addParam("response_type", "code");
                enc.addParam("client_id", conf.getMUAUnionAuthClientId());
                enc.addParam("redirect_uri", conf.getServerExternalUri().toString());
                enc.addParam("state", state.toString());
                MUA2FA.LOGGER.info(MARKER, "Redirecting player {} to mua union auth page ...", state.id());
                return res.sendRedirect("https://" + MUA2FA.MUA_HOST + enc);
            });
            routes.get("/", (req, res) -> {
                var dec = new QueryStringDecoder(req.uri());
                var decParams = dec.parameters();
                var state = OAuthState.fromString(Iterables.getOnlyElement(decParams.getOrDefault("state", List.of())));
                var enc = new QueryStringEncoder("/");
                enc.addParam("grant_type", "authorization_code");
                enc.addParam("code", Iterables.getOnlyElement(decParams.getOrDefault("code", List.of())));
                enc.addParam("client_id", conf.getMUAUnionAuthClientId());
                enc.addParam("client_secret", conf.getMUAUnionAuthClientSecret());
                enc.addParam("redirect_uri", conf.getServerExternalUri().toString());
                MUA2FA.LOGGER.info(MARKER, "Requesting the authorization token for player {} ...", state.name());
                var tokenClient = HttpClient.create().runOn(runOn).headers(headers -> {
                    headers.add(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED);
                    headers.add(HttpHeaderNames.ACCEPT, HttpHeaderValues.APPLICATION_JSON);
                    headers.add(HttpHeaderNames.USER_AGENT, ua);
                });
                var tokenUri = "https://" + MUA2FA.MUA_HOST + "/api/union/oauth2/token";
                var tokenBody = ByteBufFlux.fromString(Mono.fromCallable(() -> enc.toUri().getQuery()));
                var tokenRes = tokenClient.post().uri(tokenUri).send(tokenBody).responseSingle(this::json);
                var userRes = tokenRes.flatMap(json -> {
                    var token = json.get("access_token").getAsString();
                    var tokenType = json.get("token_type").getAsString();
                    MUA2FA.LOGGER.info(MARKER, "Requesting the user information for player {} ...", state.name());
                    var userClient = HttpClient.create().runOn(runOn).headers(headers -> {
                        headers.add(HttpHeaderNames.ACCEPT, HttpHeaderValues.APPLICATION_JSON);
                        headers.add(HttpHeaderNames.AUTHORIZATION, tokenType + " " + token);
                        headers.add(HttpHeaderNames.USER_AGENT, ua);
                    });
                    var userUri = "https://" + MUA2FA.MUA_HOST + "/api/union/oauth2/user";
                    return userClient.get().uri(userUri).responseSingle(this::json);
                });
                return userRes.flatMap(json -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
                    var user = MUARecord.User.CODEC.decode(JsonOps.INSTANCE, json).getOrThrow().getFirst();
                    this.records.emitNext(user, Sinks.EmitFailureHandler.FAIL_FAST);
                    MUA2FA.LOGGER.info(MARKER, "Finished the oauth process of player {}, replying ...", state.name());
                    return header.sendString(Mono.just(String.format(HTML, "#066805", state.completeHint()))).then();
                }).onErrorResume(e -> {
                    var header = res.header(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
                    MUA2FA.LOGGER.warn(MARKER, "Error thrown on processing (state: {}): {}", state, e.getMessage(), e);
                    return header.sendString(Mono.just(String.format(HTML, "#97242c", state.cancelHint()))).then();
                });
            });
        });
        MUA2FA.LOGGER.info(MARKER, STARTING);
        this.server.set(server.doOnBound(s -> MUA2FA.LOGGER.info(MARKER, STARTED, s.address())).bindNow());
    }

    @Override
    public void close() {
        var server = this.server.getAndSet(null);
        if (server != null) {
            MUA2FA.LOGGER.info(MARKER, STOPPING, server.address());
            server.onDispose().doAfterTerminate(() -> MUA2FA.LOGGER.info(MARKER, STOPPED)).subscribe();
        }
    }
}
